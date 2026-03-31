import {
  Controller,
  Get,
  Post,
  Body,
  Param,
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

  @Get('external/:userId')
  @HttpCode(HttpStatus.OK)
  async getTemplatesForUser(@Param('userId') userId: string) {
    const data = await this.service.getTemplatesForUser(userId);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post(':templateId/external-submit')
  @HttpCode(HttpStatus.OK)
  async submitFields(
    @Param('templateId') templateId: string,
    @Body() dto: SubmitExternalFieldsDto,
  ) {
    const data = await this.service.submitFields(templateId, dto);
    return SuccessHelper.createSuccessResponse(data, 'Fields submitted successfully.');
  }
}
