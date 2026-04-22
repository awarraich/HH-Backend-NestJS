import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
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
import { PresignEmployeeDocumentUploadDto } from '../dto/presign-employee-document-upload.dto';
import { ConfirmEmployeeDocumentUploadDto } from '../dto/confirm-employee-document-upload.dto';
import { ReplaceEmployeeDocumentFileDto } from '../dto/replace-employee-document-file.dto';

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

  @Post('presign-upload')
  @HttpCode(HttpStatus.OK)
  async presignUpload(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Body() dto: PresignEmployeeDocumentUploadDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.presignUpload(
      organizationId,
      employeeId,
      dto.filename,
      dto.contentType,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('confirm-upload')
  @HttpCode(HttpStatus.CREATED)
  async confirmUpload(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Body() dto: ConfirmEmployeeDocumentUploadDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.employeeDocumentsService.confirmUpload(
      organizationId,
      employeeId,
      dto.document_type_id,
      {
        key: dto.key,
        fileName: dto.file_name,
        mimeType: dto.mime_type,
        sizeBytes: dto.size_bytes,
      },
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(result, 'Document uploaded successfully');
  }

  @Get(':documentId/file-url')
  @HttpCode(HttpStatus.OK)
  async getFileUrl(
    @Param('organizationId') organizationId: string,
    @Param('employeeId') employeeId: string,
    @Param('documentId') documentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const data = await this.employeeDocumentsService.getDownloadUrl(
      organizationId,
      employeeId,
      documentId,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(data);
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
    @Body() dto: ReplaceEmployeeDocumentFileDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    const result = await this.employeeDocumentsService.replaceFile(
      organizationId,
      employeeId,
      documentId,
      {
        key: dto.key,
        fileName: dto.file_name,
        mimeType: dto.mime_type,
        sizeBytes: dto.size_bytes,
      },
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
