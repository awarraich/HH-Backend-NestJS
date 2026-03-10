import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { JobManagementService } from '../services/job-management.service';
import { CreateJobApplicationDto } from '../dto/create-job-application.dto';

/**
 * Controller at /api/job-management so that POST /api/job-management/job-applications
 * is registered by Nest (frontend and proxies often call this path on port 8000).
 */
@Controller('api/job-management')
export class JobApplicationsController {
  constructor(private readonly jobManagementService: JobManagementService) {}

  @Post('job-applications')
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() dto: CreateJobApplicationDto): Promise<unknown> {
    const result = await this.jobManagementService.createApplication(dto);
    return SuccessHelper.createSuccessResponse(result, 'Application submitted');
  }
}
