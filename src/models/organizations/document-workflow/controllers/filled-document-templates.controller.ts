import {
  Controller,
  Get,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { IsOptional, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { TemplatesService } from '../services/templates.service';

class FilledTemplatesQueryDto {
  @IsOptional()
  @IsInt()
  @Min(1)
  @Type(() => Number)
  page?: number = 1;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  limit?: number = 20;
}

@Controller('v1/api/organization/:organizationId/filled-document-templates')
@UseGuards(JwtAuthGuard)
export class FilledDocumentTemplatesController {
  constructor(private readonly templatesService: TemplatesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: FilledTemplatesQueryDto,
  ) {
    const result = await this.templatesService.findFilledTemplates(
      organizationId,
      query.page ?? 1,
      query.limit ?? 20,
    );
    return SuccessHelper.createSuccessResponse(result);
  }
}
