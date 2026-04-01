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
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import { ExternalDocumentService } from '../services/external-document.service';
import { SubmitExternalFieldsDto } from '../dto/submit-external-fields.dto';

@Controller('v1/api/documents')
@UseGuards(JwtAuthGuard)
export class ExternalDocumentController {
  constructor(private readonly service: ExternalDocumentService) {}

  /**
   * GET /v1/api/documents/my-assignments?userId=xxx
   *
   * Returns all templates assigned to this user with their role-based editable fields
   * and all filled values from all users.
   */
  @Get('my-assignments')
  @HttpCode(HttpStatus.OK)
  async getMyAssignments(@Query('userId') userId: string) {
    const data = await this.service.getMyAssignments(userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post(':templateId/submit')
  @HttpCode(HttpStatus.OK)
  async submitFields(
    @Param('templateId') templateId: string,
    @Body() dto: SubmitExternalFieldsDto,
  ) {
    const data = await this.service.submitFields(templateId, dto);
    return SuccessHelper.createSuccessResponse(data, 'Fields submitted successfully.');
  }
}
