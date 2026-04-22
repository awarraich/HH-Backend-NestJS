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

  @Get(':id/pdf/view')
  @Roles()
  async viewPdf(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Res() reply: FastifyReply,
  ) {
    const { stream, contentType, fileName } = await this.service.getPdfStream(orgId, id);
    const safeName = encodeURIComponent(fileName).replace(/%20/g, '+');
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${safeName}"`)
      .send(stream);
  }

  @Post(':id/pdf')
  @HttpCode(HttpStatus.OK)
  async uploadPdf(
    @Param('organizationId') orgId: string,
    @Param('id') id: string,
    @Req() request: RequestWithUser,
  ) {
    const multipartRequest = request as RequestWithUser & {
      isMultipart?: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string }>
      >;
    };

    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Expected multipart form data.');
    }

    const body = multipartRequest.body;
    const filePart = body?.file ?? body?.document;
    const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

    if (!singleFile?.toBuffer || !singleFile?.filename) {
      throw new BadRequestException('No file uploaded. Send a field named "file" or "document".');
    }

    const buffer = await singleFile.toBuffer();
    const data = await this.service.uploadPdf(orgId, id, buffer, singleFile.filename, buffer.length);
    return SuccessHelper.createSuccessResponse(data, 'PDF uploaded.');
  }
}
