import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  Res,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
  Request,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { OrganizationDocumentsService } from '../services/organization-documents.service';
import { OrganizationDocumentsChatService } from '../services/organization-documents-chat.service';
import { QueryOrganizationDocumentDto } from '../dto/query-organization-document.dto';
import { UpdateOrganizationDocumentDto } from '../dto/update-organization-document.dto';
import { SearchOrganizationDocumentDto } from '../dto/search-organization-document.dto';
import { ChatOrganizationDocumentDto } from '../dto/chat-organization-document.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

function extractUserId(req: RequestWithUser): string {
  const userId = req.user?.userId ?? req.user?.sub;
  if (!userId) throw new UnauthorizedException('User ID not found');
  return userId;
}

type MultipartBody = Record<
  string,
  | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string; mimetype?: string }
  | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string; mimetype?: string }>
>;

function getMultipartFieldValue(body: MultipartBody, field: string): string | undefined {
  const raw = body?.[field];
  if (typeof raw === 'object' && raw && 'value' in raw) return (raw as { value?: string }).value;
  if (typeof raw === 'string') return raw;
  return undefined;
}

@Controller('v1/api/organizations/:organizationId/compliance/documents')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class OrganizationDocumentsController {
  constructor(
    private readonly documentsService: OrganizationDocumentsService,
    private readonly chatService: OrganizationDocumentsChatService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryOrganizationDocumentDto,
  ) {
    const result = await this.documentsService.findAll(organizationId, query);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get('stats')
  @HttpCode(HttpStatus.OK)
  async getStats(@Param('organizationId') organizationId: string) {
    const result = await this.documentsService.getStats(organizationId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Get(':documentId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
  ) {
    const result = await this.documentsService.findOne(organizationId, documentId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async upload(
    @Param('organizationId') organizationId: string,
    @Req() request: FastifyRequest,
    @Request() req: RequestWithUser,
  ) {
    const userId = extractUserId(req);

    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: MultipartBody;
    };

    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Request must be multipart/form-data');
    }

    const body = multipartRequest.body!;
    const filePart = body?.file ?? body?.document;
    const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

    if (!singleFile?.toBuffer || !singleFile?.filename) {
      throw new BadRequestException('No file uploaded. Send a field named "file" or "document".');
    }

    const documentName = getMultipartFieldValue(body, 'document_name');
    const categoryId = getMultipartFieldValue(body, 'category_id');
    if (!documentName) throw new BadRequestException('document_name is required');
    if (!categoryId) throw new BadRequestException('category_id is required');

    const buffer = await singleFile.toBuffer();
    const result = await this.documentsService.upload(
      organizationId,
      {
        document_name: documentName,
        category_id: categoryId,
        is_required: getMultipartFieldValue(body, 'is_required') === 'true',
        has_expiration: getMultipartFieldValue(body, 'has_expiration') === 'true',
        expiration_date: getMultipartFieldValue(body, 'expiration_date'),
      },
      { buffer, originalFilename: singleFile.filename, mimeType: singleFile.mimetype },
      userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document uploaded successfully');
  }

  @Patch(':documentId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
    @Body() dto: UpdateOrganizationDocumentDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = extractUserId(req);
    const result = await this.documentsService.update(organizationId, documentId, dto, userId);
    return SuccessHelper.createSuccessResponse(result, 'Document updated successfully');
  }

  @Post(':documentId/replace')
  @HttpCode(HttpStatus.OK)
  async replaceFile(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
    @Req() request: FastifyRequest,
    @Request() req: RequestWithUser,
  ) {
    const userId = extractUserId(req);

    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: MultipartBody;
    };

    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Request must be multipart/form-data');
    }

    const body = multipartRequest.body!;
    const filePart = body?.file ?? body?.document;
    const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

    if (!singleFile?.toBuffer || !singleFile?.filename) {
      throw new BadRequestException('No file uploaded.');
    }

    const buffer = await singleFile.toBuffer();
    const result = await this.documentsService.replaceFile(
      organizationId,
      documentId,
      { buffer, originalFilename: singleFile.filename, mimeType: singleFile.mimetype },
      userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document file replaced successfully');
  }

  @Delete(':documentId')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
    @Request() req: RequestWithUser,
  ) {
    const userId = extractUserId(req);
    await this.documentsService.remove(organizationId, documentId, userId);
    return SuccessHelper.createSuccessResponse(null, 'Document deleted successfully');
  }

  @Get(':documentId/download')
  @HttpCode(HttpStatus.OK)
  async download(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
    @Res() reply: FastifyReply,
  ) {
    const { stream, contentType, file_name } = await this.documentsService.getFileForDownload(
      organizationId,
      documentId,
    );
    const safeName = file_name.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
    const encodedName = encodeURIComponent(file_name);
    return reply
      .header('Content-Type', contentType)
      .header(
        'Content-Disposition',
        `attachment; filename="${safeName}"; filename*=UTF-8''${encodedName}`,
      )
      .send(stream);
  }

  @Get(':documentId/view')
  @HttpCode(HttpStatus.OK)
  async view(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
    @Res() reply: FastifyReply,
  ) {
    const { stream, contentType, file_name } = await this.documentsService.getFileForDownload(
      organizationId,
      documentId,
    );
    const safeName = file_name.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${safeName}"`)
      .send(stream);
  }

  @Post(':documentId/scan')
  @HttpCode(HttpStatus.OK)
  async scan(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
  ) {
    const result = await this.documentsService.scanDocument(organizationId, documentId);
    return SuccessHelper.createSuccessResponse(result, 'Document scanned successfully');
  }

  @Post('search')
  @HttpCode(HttpStatus.OK)
  async search(
    @Param('organizationId') organizationId: string,
    @Body() dto: SearchOrganizationDocumentDto,
  ) {
    const result = await this.documentsService.semanticSearch(
      organizationId,
      dto.query,
      dto.category_id,
      dto.limit,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('chat')
  @HttpCode(HttpStatus.OK)
  async chat(
    @Param('organizationId') organizationId: string,
    @Body() dto: ChatOrganizationDocumentDto,
  ) {
    const result = await this.chatService.chat(
      organizationId,
      dto.message,
      dto.history,
      dto.document_ids,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
