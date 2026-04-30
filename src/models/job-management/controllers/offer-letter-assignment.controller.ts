import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  Patch,
  Post,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../common/guards/organization-role.guard';
import { Roles } from '../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { extractRequestSignatureMetadata } from '../../../common/utils/extract-request-metadata';
import { OfferLetterAssignmentService } from '../services/offer-letter-assignment.service';
import { OfferLetterArchiveService } from '../services/offer-letter-archive.service';
import { CreateOfferLetterAssignmentDto } from '../dto/create-offer-letter-assignment.dto';
import { FillOfferLetterFieldsDto } from '../dto/fill-offer-letter-fields.dto';
import { Employee } from '../../employees/entities/employee.entity';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
};

/**
 * Organization-scoped CRUD for offer-letter assignments (one per offer sent
 * to a specific job application).
 */
@Controller(
  'v1/api/organizations/:organizationId/job-applications/:applicationId/offer-letter-assignments',
)
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'ADMIN', 'MANAGER')
export class OfferLetterAssignmentController {
  constructor(
    private readonly service: OfferLetterAssignmentService,
    private readonly archiveService: OfferLetterArchiveService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(
    @Param('organizationId') orgId: string,
    @Param('applicationId') applicationId: string,
  ) {
    const data = await this.service.findForApplication(orgId, applicationId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.findOne(orgId, id);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') orgId: string,
    @Param('applicationId') applicationId: string,
    @Body() dto: CreateOfferLetterAssignmentDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.create(orgId, applicationId, dto, userId);
    return SuccessHelper.createSuccessResponse(
      data,
      'Offer letter assignment created.',
    );
  }

  @Patch(':id/fill')
  @HttpCode(HttpStatus.OK)
  async fill(
    @Param('id') id: string,
    @Body() dto: FillOfferLetterFieldsDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const { ip, userAgent } = extractRequestSignatureMetadata(req);
    const data = await this.service.fillFields(id, userId, dto, {
      requestMetadata: { ip, userAgent },
    });
    return SuccessHelper.createSuccessResponse(data, 'Fields saved.');
  }

  @Patch(':id/void')
  @HttpCode(HttpStatus.OK)
  async void(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.void(orgId, id);
    return SuccessHelper.createSuccessResponse(data, 'Assignment voided.');
  }

  /**
   * Retry archiving the signed PDF into the applicant's HR File. The
   * post-completion hook fires automatically when status flips to
   * `completed`, but this endpoint covers two cases the auto-hook can't:
   *
   *  1. The assignment was completed BEFORE the auto-hook was deployed —
   *     no archive row exists and the hook won't re-fire on its own.
   *  2. The auto-hook errored mid-flight (S3 hiccup, missing employee
   *     row, etc.) and HR has since fixed the precondition.
   *
   * Idempotent — if the EmployeeDocument already exists at the
   * deterministic S3 key, returns it without writing anything.
   */
  @Post(':id/archive')
  @HttpCode(HttpStatus.OK)
  async archive(@Param('id') id: string) {
    const result = await this.archiveService.archive(id);
    if (!result) {
      // Returns 200 with explanatory body instead of throwing — HR will
      // see "no employee row yet" / "OFFER_LETTER type missing" without
      // a stack trace. Backend logs carry the specific reason.
      return SuccessHelper.createSuccessResponse(
        { archived: false },
        'Archive skipped — see backend logs for the precondition that failed (assignment status, applicant_user_id, employee row, or OFFER_LETTER doc type).',
      );
    }
    return SuccessHelper.createSuccessResponse(
      { archived: true, employee_document_id: result.id, file_name: result.file_name },
      'Signed offer letter archived to HR File.',
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    await this.service.delete(orgId, id);
    return SuccessHelper.createSuccessResponse(null, 'Assignment deleted.');
  }
}

/**
 * Admin-scoped read of an employee's role-filler offer letter assignments.
 * Returns the same DTO shape as `/me/offer-letter-assignments` (with `myRoles`
 * populated for the target employee), so the org admin's Signed Documents tab
 * can render role-filler signatures alongside the candidate-side signatures
 * (which come from the job applications endpoint).
 */
@Controller(
  'v1/api/organizations/:organizationId/employees/:employeeId/offer-letter-assignments',
)
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'ADMIN', 'MANAGER')
export class EmployeeOfferLetterAssignmentsController {
  constructor(
    private readonly service: OfferLetterAssignmentService,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async list(
    @Param('organizationId') orgId: string,
    @Param('employeeId') employeeId: string,
  ) {
    const employee = await this.employeeRepo.findOne({
      where: { id: employeeId, organization_id: orgId },
    });
    if (!employee) {
      throw new NotFoundException('Employee not found in this organization');
    }
    const data = await this.service.findForUserInOrganization(
      orgId,
      employee.user_id,
    );
    return SuccessHelper.createSuccessResponse(data);
  }
}
