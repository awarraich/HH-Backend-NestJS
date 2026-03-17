import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { EmployeeDocumentAccessGuard } from '../../../../common/guards/employee-document-access.guard';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { EmployeeDocumentsService } from '../services/employee-documents.service';
import { EmployeeDocumentsChatService } from '../services/employee-documents-chat.service';
import { ExpirationStatusDto } from '../dto/expiration-status.dto';
import { EmployeeDocumentsChatRequestDto } from '../dto/employee-documents-chat-request.dto';
import { UpdateEmployeeDocumentDto } from '../dto/update-employee-document.dto';

@Controller('v1/api/organizations/:organizationId/employees/:employeeId/documents')
@UseGuards(JwtAuthGuard, EmployeeDocumentAccessGuard)
export class EmployeeDocumentsController {
  constructor(
    private readonly employeeDocumentsService: EmployeeDocumentsService,
    private readonly employeeDocumentsChatService: EmployeeDocumentsChatService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getRequiredDocuments(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.getRequiredDocuments(
      organizationId,
      employeeId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('document-types-by-tags')
  @HttpCode(HttpStatus.OK)
  async getDocumentTypesByEmployeeTags(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.getDocumentTypesByEmployeeTags(
      organizationId,
      employeeId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get('inservice-trainings-by-tags')
  @HttpCode(HttpStatus.OK)
  async getInserviceTrainingsByEmployeeTags(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.getInserviceTrainingsByEmployeeTags(
      organizationId,
      employeeId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('expiration-status')
  @HttpCode(HttpStatus.OK)
  async getExpirationStatus(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Body() dto: ExpirationStatusDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.getExpirationStatus(
      organizationId,
      employeeId,
      dto.document_ids,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('chat')
  @HttpCode(HttpStatus.OK)
  async chat(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Body() dto: EmployeeDocumentsChatRequestDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const history = dto.history as { role: 'user' | 'assistant'; content: string }[] | undefined;
    const result = await this.employeeDocumentsChatService.chat(
      organizationId,
      employeeId,
      dto.message,
      user.userId,
      history,
      dto.document_id,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('upload')
  @HttpCode(HttpStatus.CREATED)
  async upload(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Req() request: FastifyRequest,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string }>
      >;
    };

    if (multipartRequest.isMultipart?.()) {
      const body = multipartRequest.body;
      const filePart = body?.file ?? body?.document;
      const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;
      const docTypeRaw = body?.document_type_id;
      const docTypeId =
        typeof docTypeRaw === 'object' && docTypeRaw && 'value' in docTypeRaw
          ? (docTypeRaw as { value?: string }).value
          : typeof docTypeRaw === 'string'
            ? docTypeRaw
            : null;

      if (!singleFile?.toBuffer || !singleFile?.filename) {
        throw new BadRequestException('No file uploaded. Send a field named "file" or "document".');
      }
      if (!docTypeId || typeof docTypeId !== 'string') {
        throw new BadRequestException('document_type_id is required.');
      }

      const buffer = await singleFile.toBuffer();
      const mimeType = (singleFile as { mimetype?: string }).mimetype;
      const result = await this.employeeDocumentsService.upload(
        organizationId,
        employeeId,
        docTypeId,
        {
          buffer,
          originalFilename: singleFile.filename,
          mimeType,
        },
        user.userId,
      );
      return SuccessHelper.createSuccessResponse(result, 'Document uploaded successfully');
    }

    const legacyRequest = request as FastifyRequest & {
      file: () => Promise<
        { filename: string; toBuffer: () => Promise<Buffer>; mimetype?: string } | undefined
      >;
    };
    const data = await legacyRequest.file?.();
    if (!data) {
      throw new BadRequestException(
        'No file uploaded. Use multipart/form-data with field "file" and "document_type_id".',
      );
    }
    const buffer = await data.toBuffer();
    const docTypeId = (request.body as { document_type_id?: string })?.document_type_id;
    if (!docTypeId) {
      throw new BadRequestException('document_type_id is required.');
    }
    const result = await this.employeeDocumentsService.upload(
      organizationId,
      employeeId,
      docTypeId,
      {
        buffer,
        originalFilename: data.filename,
        mimeType: data.mimetype,
      },
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document uploaded successfully');
  }

  @Get(':documentId/download')
  @HttpCode(HttpStatus.OK)
  async download(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('documentId') documentId: string,
    @Res() reply: FastifyReply,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const { stream, contentType, file_name } =
      await this.employeeDocumentsService.getFileForDownload(
        organizationId,
        employeeId,
        documentId,
        user.userId,
      );
    const rawName = file_name ?? 'document';
    const safeName = rawName.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
    const encodedName = encodeURIComponent(rawName);
    return reply
      .header('Content-Type', contentType)
      .header(
        'Content-Disposition',
        `attachment; filename="${safeName}"; filename*=UTF-8''${encodedName}`,
      )
      .send(stream);
  }

  @Get(':documentId')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('documentId') documentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.findOne(
      organizationId,
      employeeId,
      documentId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Delete(':documentId')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('documentId') documentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.employeeDocumentsService.delete(organizationId, employeeId, documentId, user.userId);
    return SuccessHelper.createSuccessResponse(null, 'Document deleted successfully');
  }

  @Patch(':documentId/file')
  @HttpCode(HttpStatus.OK)
  async replaceFile(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('documentId') documentId: string,
    @Req() request: FastifyRequest,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string }>
      >;
    };

    if (multipartRequest.isMultipart?.()) {
      const body = multipartRequest.body;
      const filePart = body?.file ?? body?.document;
      const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

      if (!singleFile?.toBuffer || !singleFile?.filename) {
        throw new BadRequestException('No file uploaded. Send a field named "file" or "document".');
      }

      const buffer = await singleFile.toBuffer();
      const mimeType = (singleFile as { mimetype?: string }).mimetype;
      const result = await this.employeeDocumentsService.replaceFile(
        organizationId,
        employeeId,
        documentId,
        { buffer, originalFilename: singleFile.filename, mimeType },
        user.userId,
      );
      return SuccessHelper.createSuccessResponse(result, 'Document file replaced successfully');
    }

    const legacyRequest = request as FastifyRequest & {
      file: () => Promise<
        { filename: string; toBuffer: () => Promise<Buffer>; mimetype?: string } | undefined
      >;
    };
    const data = await legacyRequest.file?.();
    if (!data) {
      throw new BadRequestException(
        'No file uploaded. Use multipart/form-data with field "file".',
      );
    }
    const buffer = await data.toBuffer();
    const result = await this.employeeDocumentsService.replaceFile(
      organizationId,
      employeeId,
      documentId,
      { buffer, originalFilename: data.filename, mimeType: data.mimetype },
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document file replaced successfully');
  }

  @Patch(':documentId')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('documentId') documentId: string,
    @Body() dto: UpdateEmployeeDocumentDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.employeeDocumentsService.update(
      organizationId,
      employeeId,
      documentId,
      dto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document updated successfully');
  }
}
