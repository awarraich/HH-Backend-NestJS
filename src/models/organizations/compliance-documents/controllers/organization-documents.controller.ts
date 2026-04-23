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
  Request,
  UnauthorizedException,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
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
import { PresignOrganizationDocumentUploadDto } from '../dto/presign-organization-document-upload.dto';
import { ConfirmOrganizationDocumentUploadDto } from '../dto/confirm-organization-document-upload.dto';
import { ReplaceOrganizationDocumentFileDto } from '../dto/replace-organization-document-file.dto';

type RequestWithUser = FastifyRequest & { user?: { userId?: string; sub?: string } };

function extractUserId(req: RequestWithUser): string {
  const userId = req.user?.userId ?? req.user?.sub;
  if (!userId) throw new UnauthorizedException('User ID not found');
  return userId;
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

  @Post('presign-upload')
  @HttpCode(HttpStatus.OK)
  async presignUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: PresignOrganizationDocumentUploadDto,
  ) {
    const data = await this.documentsService.presignUpload(
      organizationId,
      dto.filename,
      dto.contentType,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async confirmUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: ConfirmOrganizationDocumentUploadDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = extractUserId(req);
    const result = await this.documentsService.confirmUpload(
      organizationId,
      {
        document_name: dto.document_name,
        category_id: dto.category_id,
        is_required: dto.is_required,
        has_expiration: dto.has_expiration,
        expiration_date: dto.expiration_date,
      },
      {
        key: dto.key,
        fileName: dto.file_name,
        mimeType: dto.mime_type,
        sizeBytes: dto.size_bytes,
      },
      userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document uploaded successfully');
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
    @Body() dto: ReplaceOrganizationDocumentFileDto,
    @Request() req: RequestWithUser,
  ) {
    const userId = extractUserId(req);
    const result = await this.documentsService.replaceFile(
      organizationId,
      documentId,
      {
        key: dto.key,
        fileName: dto.file_name,
        mimeType: dto.mime_type,
        sizeBytes: dto.size_bytes,
      },
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

  @Get(':documentId/file-url')
  @HttpCode(HttpStatus.OK)
  async getFileUrl(
    @Param('organizationId') organizationId: string,
    @Param('documentId') documentId: string,
  ) {
    const data = await this.documentsService.getDownloadUrl(organizationId, documentId);
    return SuccessHelper.createSuccessResponse(data);
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
