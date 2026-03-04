import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from './common/guards/organization-role.guard';
import { Roles } from './common/decorators/roles.decorator';
import { SuccessHelper } from './common/helpers/responses/success.helper';
import { JobManagementService } from './models/job-management/job-management.service';
import { CreateJobPostingDto } from './models/job-management/dto/create-job-posting.dto';
import { QueryJobPostingDto } from './models/job-management/dto/query-job-posting.dto';

/**
 * App-level job-management routes so create/list work even if JobManagementModule
 * has loading issues. Same paths as JobManagementController.
 */
@Controller('job-management')
export class AppController {
  constructor(private readonly jobManagementService: JobManagementService) {}

  @Get('health')
  @HttpCode(HttpStatus.OK)
  health() {
    return { status: 'ok', module: 'job-management' };
  }

  @Post('organization/:organizationId/job-postings')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.CREATED)
  async createJobPosting(
    @Param('organizationId') organizationId: string,
    @Body() createDto: CreateJobPostingDto,
  ) {
    const result = await this.jobManagementService.create(organizationId, createDto);
    return SuccessHelper.createSuccessResponse(result, 'Job posting created successfully');
  }

  @Get('organization/:organizationId/job-postings')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async listJobPostings(
    @Param('organizationId') organizationId: string,
    @Query() queryDto: QueryJobPostingDto,
  ) {
    const result = await this.jobManagementService.findAllByOrganization(
      organizationId,
      queryDto,
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }
}
