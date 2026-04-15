import {
  Controller,
  Get,
  Param,
  Query,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { JobManagementService } from '../services/job-management.service';

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
  constructor(private readonly jobManagementService: JobManagementService) {}

  @Get('me/job-applications')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async listMyApplications(@Req() req: FastifyRequest): Promise<unknown> {
    const userId = (req as any)?.user?.userId;
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
    const userId = (req as any)?.user?.userId;
    const application =
      await this.jobManagementService.findMyJobApplicationByIdForUser(
        userId,
        applicationId,
      );
    return SuccessHelper.createSuccessResponse(application);
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
    const userId = (req as any)?.user?.userId;
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
