import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Query,
  UseGuards,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  BadRequestException,
} from '@nestjs/common';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { InserviceTrainingService } from '../services/inservice-training.service';
import { CreateInserviceTrainingDto } from '../dto/create-inservice-training.dto';
import { UpdateInserviceTrainingDto } from '../dto/update-inservice-training.dto';
import { QueryInserviceTrainingDto } from '../dto/query-inservice-training.dto';

type MultipartField =
  | { value?: string }
  | { toBuffer?: () => Promise<Buffer>; filename?: string }
  | undefined;

function getMultipartString(field: MultipartField | MultipartField[]): string {
  if (field == null) return '';
  const single = Array.isArray(field) ? field[0] : field;
  if (single && typeof single === 'object' && 'value' in single) {
    return (single as { value?: string }).value ?? '';
  }
  return '';
}

interface MultipartFilePart {
  toBuffer: () => Promise<Buffer>;
  filename: string;
}

function getMultipartFile(
  body: Record<string, MultipartField | MultipartField[] | undefined> | undefined,
): MultipartFilePart | undefined {
  if (!body) return undefined;
  const field = body.file ?? body.document;
  if (field == null) return undefined;
  const single = Array.isArray(field) ? field[0] : field;
  if (
    single &&
    typeof single === 'object' &&
    'toBuffer' in single &&
    typeof (single as { toBuffer?: () => Promise<Buffer> }).toBuffer ===
      'function' &&
    (single as { filename?: string }).filename
  ) {
    return single as MultipartFilePart;
  }
  return undefined;
}

@Controller('v1/api/organizations/:organizationId/inservice-trainings')
@UseGuards(JwtAuthGuard, OrganizationRoleGuard)
@Roles('OWNER', 'HR', 'MANAGER')
export class InserviceTrainingsController {
  constructor(
    private readonly inserviceTrainingService: InserviceTrainingService,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Param('organizationId') organizationId: string,
    @Query() query: QueryInserviceTrainingDto,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const result = await this.inserviceTrainingService.findAll(
      organizationId,
      query,
      userId,
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get(':id/pdf')
  @HttpCode(HttpStatus.OK)
  async downloadPdf(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Res() reply: FastifyReply,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const { stream, contentType, file_name } =
      await this.inserviceTrainingService.getPdfStream(
        organizationId,
        id,
        userId,
      );
    reply.header('Content-Type', contentType);
    reply.header(
      'Content-Disposition',
      `attachment; filename="${encodeURIComponent(file_name)}"`,
    );
    return reply.send(stream);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    const result = await this.inserviceTrainingService.findOne(
      organizationId,
      id,
      userId,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Param('organizationId') organizationId: string,
    @Req() req: FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<string, MultipartField | MultipartField[]>;
    },
  ) {
    const userId = (req as any).user?.userId ?? (req as any).user?.sub ?? '';

    if (!req.isMultipart?.() || !req.body) {
      throw new BadRequestException(
        'Request must be multipart/form-data with fields: code, title, completion_frequency, and optionally description, video_url, sort_order, file (PDF).',
      );
    }

    const body = req.body;
    const code = getMultipartString(body.code);
    const title = getMultipartString(body.title);
    const description = getMultipartString(body.description);
    const completion_frequency = getMultipartString(body.completion_frequency);
    const video_url = getMultipartString(body.video_url);
    const sort_orderStr = getMultipartString(body.sort_order);
    const sort_order = sort_orderStr ? parseInt(sort_orderStr, 10) : undefined;

    const dto = plainToInstance(CreateInserviceTrainingDto, {
      code: code || undefined,
      title: title || undefined,
      description: description || undefined,
      completion_frequency: completion_frequency || undefined,
      video_url: video_url || undefined,
      sort_order: Number.isFinite(sort_order) ? sort_order : undefined,
    });

    const errors = await validate(dto);
    if (errors.length > 0) {
      const messages = errors.flatMap((e) =>
        Object.values(e.constraints ?? {}),
      );
      throw new BadRequestException(messages.join('; '));
    }

    const filePart = getMultipartFile(body);
    let file: { buffer: Buffer; originalFilename: string } | undefined;
    if (filePart) {
      try {
        const buffer = await filePart.toBuffer();
        if (buffer?.length) {
          file = { buffer, originalFilename: filePart.filename };
        }
      } catch {
        // Field "file" was present but empty or not a valid file (e.g. no stream)
        file = undefined;
      }
    }

    const result = await this.inserviceTrainingService.create(
      organizationId,
      dto,
      userId,
      file,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Inservice training created successfully',
    );
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Req() req: FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<string, MultipartField | MultipartField[]>;
    },
  ) {
    const userId = (req as any).user?.userId ?? (req as any).user?.sub ?? '';

    if (!req.isMultipart?.() || !req.body) {
      throw new BadRequestException(
        'Request must be multipart/form-data with optional fields: title, description, completion_frequency, video_url, sort_order, is_active, file (PDF).',
      );
    }

    const body = req.body;
    const titleVal = body.title != null ? getMultipartString(body.title) : undefined;
    const descriptionVal =
      body.description != null ? getMultipartString(body.description) : undefined;
    const completion_frequencyVal =
      body.completion_frequency != null
        ? getMultipartString(body.completion_frequency)
        : undefined;
    const video_urlVal =
      body.video_url != null ? getMultipartString(body.video_url) : undefined;
    const sort_orderStr =
      body.sort_order != null ? getMultipartString(body.sort_order) : undefined;
    const is_activeStr =
      body.is_active != null ? getMultipartString(body.is_active) : undefined;
    const sort_order = sort_orderStr ? parseInt(sort_orderStr, 10) : undefined;
    const is_active =
      is_activeStr === 'true'
        ? true
        : is_activeStr === 'false'
          ? false
          : undefined;

    const dto = plainToInstance(UpdateInserviceTrainingDto, {
      ...(titleVal !== undefined && { title: titleVal || undefined }),
      ...(descriptionVal !== undefined && {
        description: descriptionVal || undefined,
      }),
      ...(completion_frequencyVal !== undefined && {
        completion_frequency: completion_frequencyVal || undefined,
      }),
      ...(video_urlVal !== undefined && {
        video_url: video_urlVal === '' ? null : video_urlVal || undefined,
      }),
      ...(Number.isFinite(sort_order) && { sort_order }),
      ...(is_active !== undefined && { is_active }),
    });

    const errors = await validate(dto, { skipMissingProperties: true });
    if (errors.length > 0) {
      const messages = errors.flatMap((e) =>
        Object.values(e.constraints ?? {}),
      );
      throw new BadRequestException(messages.join('; '));
    }

    const filePart = getMultipartFile(body);
    let file: { buffer: Buffer; originalFilename: string } | undefined;
    if (filePart) {
      try {
        const buffer = await filePart.toBuffer();
        if (buffer?.length) {
          file = { buffer, originalFilename: filePart.filename };
        }
      } catch {
        file = undefined;
      }
    }

    const result = await this.inserviceTrainingService.update(
      organizationId,
      id,
      dto,
      userId,
      file,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Inservice training updated successfully',
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('organizationId') organizationId: string,
    @Param('id') id: string,
    @Req() req: FastifyRequest & { user?: { userId?: string; sub?: string } },
  ) {
    const userId = req.user?.userId ?? req.user?.sub ?? '';
    await this.inserviceTrainingService.remove(organizationId, id, userId);
    return SuccessHelper.createSuccessResponse(
      null,
      'Inservice training deleted successfully',
    );
  }
}
