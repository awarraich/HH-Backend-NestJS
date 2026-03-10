import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import { JobManagementService } from './job-management.service';
import { UpdateJobPostingDto } from './dto/update-job-posting.dto';
import { QueryJobPostingDto } from './dto/query-job-posting.dto';
import { CreateJobApplicationDto } from './dto/create-job-application.dto';

@Controller('v1/api/job-management')
export class JobManagementController {
  constructor(private readonly jobManagementService: JobManagementService) {}

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

  /** Public: submit job application (apply form). Single route; Fastify treats job-applications and job-applications/ as duplicate. */
  @Post('job-applications')
  @HttpCode(HttpStatus.CREATED)
  async createApplication(@Body() dto: CreateJobApplicationDto): Promise<unknown> {
    const result = await this.jobManagementService.createApplication(dto);
    return SuccessHelper.createSuccessResponse(result, 'Application submitted');
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

  /** List all applications for an organization (all jobs). */
  @Get('organization/:organizationId/job-applications')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'ADMIN')
  @HttpCode(HttpStatus.OK)
  async findAllApplicationsByOrganization(
    @Param('organizationId') organizationId: string,
  ): Promise<unknown> {
    const applications =
      await this.jobManagementService.findAllApplicationsByOrganization(organizationId);
    return SuccessHelper.createSuccessResponse({ applications });
  }
}
