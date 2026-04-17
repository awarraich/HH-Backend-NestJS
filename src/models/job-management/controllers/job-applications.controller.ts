import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { OptionalJwtAuthGuard } from '../../../common/guards/optional-jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { JobManagementService } from '../services/job-management.service';
import { CreateJobApplicationDto } from '../dto/create-job-application.dto';

/**
 * Controller at /api/job-management so that POST /api/job-management/job-applications
 * is registered by Nest (frontend and proxies often call this path on port 8000).
 *
 * Apply endpoint is public (guests can apply), but gated behind
 * `OptionalJwtAuthGuard` so the controller can still read the caller's user
 * id when a valid token is present — letting us durably link the application
 * to the user account that submitted it.
 */
@Controller('api/job-management')
export class JobApplicationsController {
  constructor(private readonly jobManagementService: JobManagementService) {}

  @Post('job-applications')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() dto: CreateJobApplicationDto,
    @Req() req: FastifyRequest,
  ): Promise<unknown> {
    const userId = (req as unknown as { user?: { userId?: string } }).user?.userId;
    const result = await this.jobManagementService.createApplication(
      dto,
      userId ? String(userId) : null,
    );
    return SuccessHelper.createSuccessResponse(result, 'Application submitted');
  }
}
