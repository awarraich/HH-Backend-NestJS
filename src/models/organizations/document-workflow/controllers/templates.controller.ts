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
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { TemplatesService } from '../services/templates.service';
import { TemplateAssignmentsService } from '../services/template-assignments.service';
import { CreateTemplateDto } from '../dto/create-template.dto';
import { UpdateTemplateDto } from '../dto/update-template.dto';
import { AssignTemplateUsersDto } from '../dto/assign-template-user.dto';

type RequestWithUser = FastifyRequest & {
  user?: { userId?: string; sub?: string };
  body?: Record<
    string,
    | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
    | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string }>
  >;
  isMultipart?: () => boolean;
};

@Controller('v1/api/organizations/:organizationId/document-workflow/templates')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class TemplatesController {
  constructor(
    private readonly service: TemplatesService,
    private readonly assignmentsService: TemplateAssignmentsService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') orgId: string,
    @Query('purpose') purpose?: string,
  ) {
    // Accept only the known values; anything else is ignored so a bad query
    // string can't 500 the list endpoint.
    const normalized: 'document' | 'applicant_form' | undefined =
      purpose === 'applicant_form' || purpose === 'document'
        ? purpose
        : undefined;
    const data = await this.service.findAll(orgId, normalized);
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
    @Body() dto: CreateTemplateDto,
    @Req() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.service.create(orgId, dto, userId);
    return SuccessHelper.createSuccessResponse(data, 'Template created.');
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Body() dto: UpdateTemplateDto,
  ) {
    const data = await this.service.update(orgId, id, dto);
    return SuccessHelper.createSuccessResponse(data, 'Template updated.');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    await this.service.delete(orgId, id);
    return SuccessHelper.createSuccessResponse(null, 'Template deleted.');
  }

  @Get(':id/assignments')
  @HttpCode(HttpStatus.OK)
  async getAssignments(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.assignmentsService.findAllForTemplate(orgId, id);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post(':id/assign')
  @HttpCode(HttpStatus.CREATED)
  async assignUsers(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Body() dto: AssignTemplateUsersDto,
    @Req() req: RequestWithUser,
  ) {
    const userId = req.user?.userId ?? req.user?.sub;
    if (!userId) throw new UnauthorizedException('User ID not found');
    const data = await this.assignmentsService.assign(orgId, id, dto, userId);
    return SuccessHelper.createSuccessResponse(data, 'Users assigned to template.');
  }

  @Delete(':id/assign/:assignmentId')
  @HttpCode(HttpStatus.OK)
  async unassignUser(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Param('assignmentId') assignmentId: string,
  ) {
    await this.assignmentsService.unassign(orgId, id, assignmentId);
    return SuccessHelper.createSuccessResponse(null, 'User unassigned from template.');
  }

  /**
   * Returns the signed S3 URL as JSON.
   * Prefer this for pdf.js / react-pdf / any fetch()-based viewer:
   * a redirect would taint the request origin to `null` during CORS preflight
   * and S3 would reject it.
   */
  @Get(':id/pdf/file-url')
  @Roles()
  async getPdfFileUrl(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
  ) {
    const data = await this.service.getPdfSignedUrl(orgId, id);
    return SuccessHelper.createSuccessResponse(data);
  }

  /**
   * Streams the PDF bytes through the backend.
   *
   * Note on the earlier 302-to-S3 approach: a cross-origin redirect during a
   * fetch()-based viewer's CORS request taints the request origin to `null`,
   * which S3 can't match against the bucket's per-origin CORS rules. Proxying
   * the bytes through the backend keeps the response same-origin-friendly
   * (our app-level CORS applies) and unblocks react-pdf / pdf.js range reads.
   * For public media (images, videos via <img>/<video>) the redirect pattern
   * is fine — use /pdf/file-url when you want the signed S3 URL as JSON.
   */
  @Get(':id/pdf/view')
  @Roles()
  async viewPdf(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Res() reply: FastifyReply,
  ) {
    const { buffer, contentType, fileName } = await this.service.getPdfBuffer(orgId, id);
    const safeName = fileName.replace(/["\\]/g, '_');
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${safeName}"`)
      .header('Accept-Ranges', 'bytes')
      .header('Cache-Control', 'private, max-age=60')
      .send(buffer);
  }

  @Post(':id/pdf/presign-upload')
  @HttpCode(HttpStatus.OK)
  async presignPdfUpload(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Body() body: { filename: string; contentType: string },
  ) {
    if (!body?.filename || typeof body.filename !== 'string') {
      throw new BadRequestException('filename is required');
    }
    if (!body?.contentType || typeof body.contentType !== 'string') {
      throw new BadRequestException('contentType is required');
    }
    const data = await this.service.presignPdfUpload(orgId, id, body.filename, body.contentType);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post(':id/pdf')
  @HttpCode(HttpStatus.OK)
  async confirmPdfUpload(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Body() body: { key: string; file_name: string; size_bytes?: number },
  ) {
    if (!body?.key || typeof body.key !== 'string') {
      throw new BadRequestException('key is required');
    }
    if (!body?.file_name || typeof body.file_name !== 'string') {
      throw new BadRequestException('file_name is required');
    }
    const data = await this.service.confirmPdfUpload(orgId, id, {
      key: body.key,
      fileName: body.file_name,
      ...(body.size_bytes != null ? { sizeBytes: body.size_bytes } : {}),
    });
    return SuccessHelper.createSuccessResponse(data, 'PDF uploaded.');
  }
}
