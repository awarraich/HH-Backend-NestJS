import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  Req,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import type { FastifyRequest, FastifyReply } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../common/guards/organization-role.guard';
import { Roles } from '../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { JobManagementService } from '../services/job-management.service';
import { JobApplicationDocumentStorageService } from '../services/job-application-document-storage.service';
import { CreateJobPostingDto } from '../dto/create-job-posting.dto';
import { UpdateJobPostingDto } from '../dto/update-job-posting.dto';
import { QueryJobPostingDto } from '../dto/query-job-posting.dto';
import { QueryJobApplicationsDto } from '../dto/query-job-applications.dto';
import { CreateJobApplicationDto } from '../dto/create-job-application.dto';
import { UpdateJobApplicationDto } from '../dto/update-job-application.dto';
import { SendInterviewInviteDto } from '../dto/send-interview-invite.dto';

@Controller('v1/api/job-management')
export class JobManagementController {
  constructor(
    private readonly jobManagementService: JobManagementService,
    private readonly jobApplicationDocumentStorage: JobApplicationDocumentStorageService,
  ) {}

  @Post('organization/:organizationId/job-postings')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() createDto: CreateJobPostingDto,
  ): Promise<unknown> {
    const result = await this.jobManagementService.create(organizationId, createDto);
    return SuccessHelper.createSuccessResponse(result, 'Job posting created successfully');
  }

  @Get('organization/:organizationId/job-postings')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async findAllByOrganization(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryJobPostingDto,
  ): Promise<unknown> {
    const result = await this.jobManagementService.findAllByOrganization(organizationId, {
      search: query.search,
      status: query.status,
      page: query.page ?? 1,
      limit: query.limit ?? 20,
    });
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get('organization/:organizationId/job-postings/:id')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ): Promise<unknown> {
    const result = await this.jobManagementService.findOne(organizationId, id);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Patch('organization/:organizationId/job-postings/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() updateDto: UpdateJobPostingDto,
  ): Promise<unknown> {
    const result = await this.jobManagementService.update(organizationId, id, updateDto);
    return SuccessHelper.createSuccessResponse(result, 'Job posting updated');
  }

  @Delete('organization/:organizationId/job-postings/:id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
  ): Promise<void> {
    await this.jobManagementService.remove(organizationId, id);
  }

  /**
   * Get organization job application form fields (public for apply form; also used by setup page).
   * Handles both /fields and /fields/ for client compatibility.
   */
  @Get('organization/:organizationId/application-form/fields')
  @HttpCode(HttpStatus.OK)
  async getApplicationFormFields(
    @Param('organizationId') organizationId: string,
  ): Promise<unknown> {
    const fields = await this.jobManagementService.getApplicationFormFields(organizationId);
    return SuccessHelper.createSuccessResponse(fields);
  }

  /**
   * Set organization job application form fields (Application Form Setup).
   */
  @Patch('organization/:organizationId/application-form/fields')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async setApplicationFormFields(
    @Param('organizationId') organizationId: string,
    @Body() body: { fields: Record<string, unknown>[] },
  ): Promise<unknown> {
    const fields = await this.jobManagementService.setApplicationFormFields(
      organizationId,
      body.fields ?? [],
    );
    return SuccessHelper.createSuccessResponse(fields, 'Application form fields saved');
  }

  /**
   * Public: upload a job application document (resume, cover letter, etc.).
   * With Fastify multipart attachFieldsToBody: true, the file is on request.body.
   */
  @Post('job-applications/upload-document')
  @HttpCode(HttpStatus.CREATED)
  async uploadApplicationDocument(@Req() request: FastifyRequest): Promise<unknown> {
    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string; _buf?: Buffer }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string; _buf?: Buffer }>
      >;
    };

    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Content-Type must be multipart/form-data');
    }

    const body = multipartRequest.body;
    const filePart = body?.file ?? body?.document;
    const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

    if (!singleFile?.filename) {
      throw new BadRequestException('No file uploaded. Send a field named "file" or "document".');
    }

    const ext = path.extname(singleFile.filename).toLowerCase();
    if (ext !== '.pdf') {
      throw new BadRequestException(
        'Only PDF files are allowed for job application and offer letter documents.',
      );
    }

    const buffer =
      singleFile._buf != null
        ? singleFile._buf
        : typeof singleFile.toBuffer === 'function'
          ? await singleFile.toBuffer()
          : null;
    if (!buffer || !Buffer.isBuffer(buffer)) {
      throw new BadRequestException('Could not read file data');
    }

    const result = await this.jobApplicationDocumentStorage.saveDocument(
      buffer,
      singleFile.filename,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document uploaded');
  }

  /** Public: serve a job application document by filename (local storage only; S3 uses direct URL). */
  @Get('job-applications/documents/files/:filename')
  @HttpCode(HttpStatus.OK)
  async serveApplicationDocument(
    @Param('filename') filename: string,
    @Query('disposition') disposition: string | undefined,
    @Res() reply: FastifyReply,
  ): Promise<unknown> {
    const filePath = this.jobApplicationDocumentStorage.getLocalFilePath(filename);
    if (!filePath) throw new NotFoundException('File not found');
    const ext = path.extname(filename).toLowerCase();
    const contentType: Record<string, string> = {
      '.pdf': 'application/pdf',
      '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.txt': 'text/plain',
    };
    const dispositionType = disposition === 'inline' ? 'inline' : 'attachment';
    return reply
      .header('Content-Type', contentType[ext] ?? 'application/octet-stream')
      .header('Content-Disposition', `${dispositionType}; filename="${encodeURIComponent(filename)}"`)
      .send(fs.createReadStream(filePath));
  }

  /** Public: submit job application (apply form). Single route; Fastify treats job-applications and job-applications/ as duplicate. */
  @Post('job-applications')
  @HttpCode(HttpStatus.CREATED)
  async createApplication(@Body() dto: CreateJobApplicationDto): Promise<unknown> {
    const result = await this.jobManagementService.createApplication(dto);
    return SuccessHelper.createSuccessResponse(result, 'Application submitted');
  }

  /** Employee: list applications submitted by a given auth user id (frontend: `/users/:userId/job-applications`). */
  @Get('users/:userId/job-applications')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async findMyJobApplicationsByUserId(@Param('userId') userId: string): Promise<unknown> {
    const applications = await this.jobManagementService.findMyJobApplicationsByUserId(userId);
    return SuccessHelper.createSuccessResponse(applications);
  }

  /** Candidate: accept or decline an offer on their own application. */
  @Patch('users/:userId/job-applications/:applicationId/offer-decision')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async respondToOfferAsCandidate(
    @Param('userId') userId: string,
    @Param('applicationId') applicationId: string,
    @Body() body: { decision: 'accept' | 'decline'; reason?: string | null },
  ): Promise<unknown> {
    const decision = body?.decision === 'decline' ? 'decline' : 'accept';
    const reason =
      decision === 'decline' && typeof body?.reason === 'string'
        ? body.reason
        : null;
    const result = await this.jobManagementService.acceptOfferAsCandidate(
      userId,
      applicationId,
      decision,
      reason,
    );
    return SuccessHelper.createSuccessResponse(
      { id: result.id, status: result.status, decline_reason: result.decline_reason },
      decision === 'accept' ? 'Offer accepted' : 'Offer declined',
    );
  }

  /** List applications for a job posting (organization). */
  @Get('organization/:organizationId/job-postings/:jobId/applications')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async findApplicationsByJobPosting(
    @Param('organizationId') organizationId: string,
    @Param('jobId') jobId: string,
  ): Promise<unknown> {
    const applications = await this.jobManagementService.findApplicationsByJobPosting(
      organizationId,
      jobId,
    );
    return SuccessHelper.createSuccessResponse({
      applications,
      job_posting: applications[0]?.job_posting ?? null,
    });
  }

  /**
   * List applications for an organization (all jobs) with pagination, search, and status filter.
   *
   * Query params (all optional):
   *   - page (default 1), limit (default 25, max 100)
   *   - status: concrete state | "offers" (any offer-lifecycle state)
   *   - q: case-insensitive search on applicant name / email / job title
   *   - job_posting_id: filter to a single job
   *
   * Response `data`: `{ applications, page, limit, total, has_more, total_by_status }`.
   */
  @Get('organization/:organizationId/job-applications')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async findAllApplicationsByOrganization(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryJobApplicationsDto,
  ): Promise<unknown> {
    const result = await this.jobManagementService.findAllApplicationsByOrganization(
      organizationId,
      query,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  /** Update job application (e.g. status: rejected | interview | offer_sent). Persists so reload keeps it. */
  @Patch('organization/:organizationId/job-applications/:id')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async updateApplicationStatus(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: UpdateJobApplicationDto,
  ): Promise<unknown> {
    const result = await this.jobManagementService.updateApplicationStatus(organizationId, id, dto);
    return SuccessHelper.createSuccessResponse(result, 'Application status updated');
  }

  /**
   * Send interview invite email to applicant (Schedule Interview modal).
   * POST organization/:organizationId/job-applications/:id/send-interview-invite
   */
  @Post('organization/:organizationId/job-applications/:id/send-interview-invite')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async sendInterviewInvite(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: SendInterviewInviteDto,
  ): Promise<unknown> {
    const result = await this.jobManagementService.sendInterviewInviteEmail(
      organizationId,
      id,
      dto,
    );
    return SuccessHelper.createSuccessResponse(result, result.message);
  }

}
