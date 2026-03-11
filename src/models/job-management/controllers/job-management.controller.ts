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
import { CreateJobApplicationDto } from '../dto/create-job-application.dto';
import { UpdateJobApplicationDto } from '../dto/update-job-application.dto';

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
    return reply
      .header('Content-Type', contentType[ext] ?? 'application/octet-stream')
      .header('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`)
      .send(fs.createReadStream(filePath));
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
}
