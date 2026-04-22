import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { extractUserId } from '../../../common/utils/extract-user-id';
import { extractRequestSignatureMetadata } from '../../../common/utils/extract-request-metadata';
import { JobManagementService } from '../services/job-management.service';
import { OfferLetterAssignmentService } from '../services/offer-letter-assignment.service';

/**
 * Applicant self-service endpoints. Scoped to the caller via JWT.
 * Mounted under `api/...` (the non-versioned prefix the frontend uses).
 *
 * IMPORTANT: callers must NOT use a trailing slash. Fastify in this project
 * is configured strictly (see `main.ts`), and the frontend has been updated
 * to match — keep these route paths slash-free.
 */
@Controller('api/job-management')
export class ApplicantJobManagementController {
  constructor(
    private readonly jobManagementService: JobManagementService,
    private readonly offerLetterAssignmentService: OfferLetterAssignmentService,
  ) {}

  @Get('me/job-applications')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async listMyApplications(@Req() req: FastifyRequest): Promise<unknown> {
    const userId = extractUserId(req);
    const applications =
      await this.jobManagementService.findMyJobApplicationsByUserId(userId);
    return SuccessHelper.createSuccessResponse(applications);
  }

  @Get('me/job-applications/:applicationId')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMyApplication(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
  ): Promise<unknown> {
    const userId = extractUserId(req);
    const application =
      await this.jobManagementService.findMyJobApplicationByIdForUser(
        userId,
        applicationId,
      );
    return SuccessHelper.createSuccessResponse(application);
  }

  /**
   * Return the offer letter assignment attached to the caller's own job
   * application (template snapshot + field values + role assignments). The
   * frontend renders this via `OfferLetterFiller` in read-only mode so the
   * applicant sees the PDF with signature placeholders and any values
   * already filled by assignees — instead of the bare template PDF.
   */
  @Get('me/job-applications/:applicationId/offer-letter')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMyOfferLetter(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
  ): Promise<unknown> {
    const userId = extractUserId(req);
    const data = await this.offerLetterAssignmentService.findForApplicant(
      String(userId),
      applicationId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  /**
   * Stream the offer letter PDF attached to the caller's own job application.
   * The applicant is NOT one of the offer_letter_assignment_roles (those are
   * internal HR / supervisors / external signers), so the role-scoped
   * `/v1/api/me/offer-letter-assignments/:id/pdf` endpoint rejects them. This
   * endpoint authorises by matching the auth'd user's email against
   * `application.applicant_email` before streaming the PDF.
   */
  @Get('me/job-applications/:applicationId/offer-letter/pdf')
  @UseGuards(JwtAuthGuard)
  async viewMyOfferLetterPdf(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
    @Query('disposition') disposition: string | undefined,
    @Query('format') format: string | undefined,
    @Res() reply: FastifyReply,
  ) {
    const userId = extractUserId(req);
    // `?format=raw` returns untouched template bytes — used by the in-app
    // OfferLetterFiller viewer which layers its own overlays. Default
    // (`rendered`) bakes overlays into the PDF so downloads / browser opens
    // show the signature placeholders and filled values inline.
    const raw = format === 'raw';
    const { buffer, contentType, fileName } =
      await this.offerLetterAssignmentService.getPdfForApplicant(
        String(userId),
        applicationId,
        { raw },
      );
    const safeName = encodeURIComponent(fileName).replace(/%20/g, '+');
    // Honour `?disposition=attachment` so the Download button forces a save
    // dialog; default is inline viewing in the browser's PDF plugin.
    const mode = disposition === 'attachment' ? 'attachment' : 'inline';
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `${mode}; filename="${safeName}"`)
      .send(buffer);
  }

  /**
   * Save the applicant's e-signature (captured via the signature canvas in
   * the Sign Offer Letter modal) onto their application. Persisted on
   * `offer_details.applicantSignature`; baked into the rendered PDF so
   * anyone opening it sees the signature.
   */
  @Post('me/job-applications/:applicationId/offer-letter/sign')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async signMyOfferLetter(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
    @Body()
    body: {
      signatureDataUrl?: string;
      consentVersion?: string;
      consentAccepted?: boolean;
    },
  ): Promise<unknown> {
    const userId = extractUserId(req);
    const signatureDataUrl = (body?.signatureDataUrl ?? '').trim();
    if (!signatureDataUrl) {
      throw new BadRequestException('signatureDataUrl is required.');
    }
    if (body?.consentAccepted !== true) {
      throw new BadRequestException(
        'You must accept the electronic signature consent before signing.',
      );
    }
    const consentVersion = (body?.consentVersion ?? '').trim();
    if (!consentVersion) {
      throw new BadRequestException('consentVersion is required.');
    }
    const { ip, userAgent } = extractRequestSignatureMetadata(req);
    const result = await this.offerLetterAssignmentService.saveApplicantSignature(
      String(userId),
      applicationId,
      signatureDataUrl,
      {
        consentVersion,
        ip,
        userAgent,
      },
    );
    return SuccessHelper.createSuccessResponse(result, 'Signature saved.');
  }

  /**
   * Accept a PDF upload of the applicant's hand-signed offer letter (for the
   * print/scan/upload flow). Delegates storage to the existing job-application
   * document storage service; records the URL + metadata on
   * `offer_details.uploadedSignedOfferLetter`.
   */
  @Post('me/job-applications/:applicationId/offer-letter/upload-signed')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async uploadSignedOfferLetter(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
    @Body() body: { key: string; file_name: string },
  ): Promise<unknown> {
    const userId = extractUserId(req);
    if (!body?.key || typeof body.key !== 'string') {
      throw new BadRequestException('key is required');
    }
    if (!body?.file_name || typeof body.file_name !== 'string') {
      throw new BadRequestException('file_name is required');
    }
    if (!body.file_name.toLowerCase().endsWith('.pdf')) {
      throw new BadRequestException('Only PDF files are allowed.');
    }
    const result =
      await this.offerLetterAssignmentService.saveApplicantUploadedSignedOfferLetter(
        String(userId),
        applicationId,
        { key: body.key, fileName: body.file_name },
      );
    return SuccessHelper.createSuccessResponse(result, 'Signed offer letter uploaded.');
  }

  /**
   * Clear the applicant's e-signature on their offer letter response, so
   * they can switch to the upload flow (or just undo an accidental sign).
   */
  @Delete('me/job-applications/:applicationId/offer-letter/sign')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async clearMyOfferLetterSignature(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
  ): Promise<unknown> {
    const userId = extractUserId(req);
    await this.offerLetterAssignmentService.clearApplicantSignature(
      String(userId),
      applicationId,
    );
    return SuccessHelper.createSuccessResponse({}, 'Signature removed.');
  }

  /**
   * Clear the applicant's uploaded signed-copy PDF, so they can switch to
   * e-signing instead.
   */
  @Delete('me/job-applications/:applicationId/offer-letter/upload-signed')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async clearMyUploadedSignedOfferLetter(
    @Req() req: FastifyRequest,
    @Param('applicationId') applicationId: string,
  ): Promise<unknown> {
    const userId = extractUserId(req);
    await this.offerLetterAssignmentService.clearApplicantUploadedSignedOfferLetter(
      String(userId),
      applicationId,
    );
    return SuccessHelper.createSuccessResponse({}, 'Uploaded copy removed.');
  }

  /**
   * Stub — returns empty list until the OnboardingAssignment feature ships.
   * Frontend treats empty list as "HR is preparing your onboarding documents."
   */
  @Get('me/onboarding-assignments')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async listMyOnboardingAssignments(
    @Req() req: FastifyRequest,
    @Query('job_application_id') jobApplicationId?: string,
  ): Promise<unknown> {
    const userId = extractUserId(req);
    if (jobApplicationId && userId) {
      // Verify the application belongs to this user — throws 404 if not.
      await this.jobManagementService.findMyJobApplicationByIdForUser(
        userId,
        jobApplicationId,
      );
    }
    return SuccessHelper.createSuccessResponse({ results: [] });
  }
}
