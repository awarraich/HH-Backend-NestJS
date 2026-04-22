import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { InserviceTrainingService } from '../services/inservice-training.service';
import { CreateInserviceTrainingDto } from '../dto/create-inservice-training.dto';
import { UpdateInserviceTrainingDto } from '../dto/update-inservice-training.dto';
import { QueryInserviceTrainingDto } from '../dto/query-inservice-training.dto';
import { PresignInserviceUploadDto } from '../dto/presign-inservice-upload.dto';

function userIdFromReq(req: FastifyRequest & { user?: { userId?: string; sub?: string } }): string {
  return req.user?.userId ?? req.user?.sub ?? '';
}

@Controller('v1/api/organizations/:organizationId/inservice-trainings')
@UseGuards(JwtAuthGuard)
export class InserviceTrainingsController {
  constructor(private readonly inserviceTrainingService: InserviceTrainingService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryInserviceTrainingDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    const result = await this.inserviceTrainingService.findAll(organizationId, query, userId);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Post('presign-upload')
  @HttpCode(HttpStatus.OK)
  async presignUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: PresignInserviceUploadDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    const data = await this.inserviceTrainingService.presignUpload(
      organizationId,
      dto.inservice_id ?? 'new',
      dto.filename,
      dto.contentType,
      userId,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':id/pdf-url')
  @HttpCode(HttpStatus.OK)
  async getPdfUrl(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Query('fileIndex') fileIndexStr: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    const fileIndex = parseInt(fileIndexStr, 10) || 0;
    const data = await this.inserviceTrainingService.getPdfFileUrl(
      organizationId,
      id,
      userId,
      fileIndex,
    );
    return SuccessHelper.createSuccessResponse(data);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    const result = await this.inserviceTrainingService.findOne(organizationId, id, userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Body() dto: CreateInserviceTrainingDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    const result = await this.inserviceTrainingService.create(
      organizationId,
      dto,
      userId,
      dto.pdf_files,
    );
    return SuccessHelper.createSuccessResponse(result, 'Inservice training created successfully');
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Body() dto: UpdateInserviceTrainingDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    const result = await this.inserviceTrainingService.update(
      organizationId,
      id,
      dto,
      userId,
      dto.pdf_files,
    );
    return SuccessHelper.createSuccessResponse(result, 'Inservice training updated successfully');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = userIdFromReq(req);
    await this.inserviceTrainingService.remove(organizationId, id, userId);
    return SuccessHelper.createSuccessResponse(null, 'Inservice training deleted successfully');
  }
}
