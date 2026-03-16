import {
  Controller,
  Get,
  Put,
  Post,
  Body,
  Param,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
  UnauthorizedException,
  InternalServerErrorException,
  HttpException,
  Logger,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { OrganizationCompanyProfileService } from '../services/organization-company-profile.service';
import { UpdateOrganizationCompanyProfileDto } from '../dto/update-organization-company-profile.dto';

@Controller('v1/api/organizations/:organizationId/company-profile')
export class OrganizationCompanyProfileController {
  private readonly logger = new Logger(OrganizationCompanyProfileController.name);

  constructor(private readonly companyProfileService: OrganizationCompanyProfileService) {}

  /** Re-throw HTTP exceptions; wrap unexpected errors in 500 and log. */
  private handleError(error: unknown, context: string): never {
    if (error instanceof HttpException) throw error;
    const message = error instanceof Error ? error.message : String(error);
    const stack = error instanceof Error ? error.stack : undefined;
    this.logger.error(`[${context}] ${message}`, stack);
    throw new InternalServerErrorException(
      'An error occurred while processing your request. Please try again later.',
    );
  }

  /** Public profile (no auth); for public profile page. :organizationId can be UUID or slug (URL-friendly name). */
  @Get('public')
  @HttpCode(HttpStatus.OK)
  async getPublic(@Param('organizationId') organizationId: string) {
    try {
      const isUuid =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          organizationId,
        );
      const data = isUuid
        ? await this.companyProfileService.getPublicByOrganizationId(organizationId)
        : await this.companyProfileService.getPublicBySlug(organizationId);
      return SuccessHelper.createSuccessResponse(data);
    } catch (error) {
      this.handleError(error, 'getPublic');
    }
  }

  @Get()
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async get(
    @Param('organizationId') organizationId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const data = await this.companyProfileService.getByOrganizationId(organizationId, userId);
      return SuccessHelper.createSuccessResponse(data);
    } catch (error) {
      this.handleError(error, 'get');
    }
  }

  @Put()
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async upsert(
    @Param('organizationId') organizationId: string,
    @Body() dto: UpdateOrganizationCompanyProfileDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const data = await this.companyProfileService.upsert(organizationId, dto, userId);
      return SuccessHelper.createSuccessResponse(data, 'Company profile saved successfully');
    } catch (error) {
      this.handleError(error, 'upsert');
    }
  }

  @Post('gallery/upload')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.CREATED)
  async uploadGalleryImage(
    @Param('organizationId') organizationId: string,
    @Req() request: FastifyRequest,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');

      const multipartRequest = request as FastifyRequest & {
        isMultipart?: () => boolean;
        body?: Record<
          string,
          | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
          | Array<{ value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }>
        >;
      };

      if (!multipartRequest.isMultipart?.()) {
        throw new BadRequestException(
          'Use multipart/form-data with field "file", optional "caption", "category".',
        );
      }

      const body = multipartRequest.body;
      const filePart = body?.file;
      const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;
      const captionRaw = body?.caption;
      const categoryRaw = body?.category;
      const caption =
        typeof captionRaw === 'object' && captionRaw && 'value' in captionRaw
          ? ((captionRaw as { value?: string }).value ?? '')
          : typeof captionRaw === 'string'
            ? captionRaw
            : '';
      const category =
        typeof categoryRaw === 'object' && categoryRaw && 'value' in categoryRaw
          ? ((categoryRaw as { value?: string }).value ?? '')
          : typeof categoryRaw === 'string'
            ? categoryRaw
            : '';

      if (!singleFile?.toBuffer || !singleFile?.filename) {
        throw new BadRequestException('No file uploaded. Send a field named "file".');
      }

      const buffer = await singleFile.toBuffer();
      const result = await this.companyProfileService.uploadGalleryImage(
        organizationId,
        { buffer, originalFilename: singleFile.filename },
        caption,
        category,
        userId,
      );
      return SuccessHelper.createSuccessResponse(result, 'Gallery image uploaded successfully');
    } catch (error) {
      this.handleError(error, 'uploadGalleryImage');
    }
  }

  @Post('videos/upload')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.CREATED)
  async uploadVideo(
    @Param('organizationId') organizationId: string,
    @Req() request: FastifyRequest,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');

      const multipartRequest = request as FastifyRequest & {
        isMultipart?: () => boolean;
        body?: Record<
          string,
          | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }
          | Array<{ value?: string; toBuffer?: () => Promise<Buffer>; filename?: string }>
        >;
      };

      if (!multipartRequest.isMultipart?.()) {
        throw new BadRequestException(
          'Use multipart/form-data with field "file", "title", optional "description", "duration", "category".',
        );
      }

      const body = multipartRequest.body;
      const filePart = body?.file;
      const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;
      const getStr = (key: string): string => {
        const raw = body?.[key];
        if (typeof raw === 'object' && raw && 'value' in raw)
          return (raw as { value?: string }).value ?? '';
        return typeof raw === 'string' ? raw : '';
      };
      const title = getStr('title');
      if (!title?.trim()) {
        throw new BadRequestException('"title" is required.');
      }

      if (!singleFile?.toBuffer || !singleFile?.filename) {
        throw new BadRequestException('No file uploaded. Send a field named "file".');
      }

      const buffer = await singleFile.toBuffer();
      const result = await this.companyProfileService.uploadVideo(
        organizationId,
        { buffer, originalFilename: singleFile.filename },
        {
          title: title.trim(),
          description: getStr('description') || undefined,
          duration: getStr('duration') || undefined,
          category: getStr('category') || undefined,
        },
        userId,
      );
      return SuccessHelper.createSuccessResponse(result, 'Video uploaded successfully');
    } catch (error) {
      this.handleError(error, 'uploadVideo');
    }
  }

  @Get('media/:type/:fileId')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async getMedia(
    @Param('organizationId') organizationId: string,
    @Param('type') type: string,
    @Param('fileId') fileId: string,
    @Res() reply: FastifyReply,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      if (type !== 'gallery' && type !== 'video') {
        throw new BadRequestException('type must be "gallery" or "video"');
      }
      const { stream, contentType, file_name } = await this.companyProfileService.getMediaStream(
        organizationId,
        type as 'gallery' | 'video',
        fileId,
        userId,
      );
      const safeName = (file_name ?? 'file').replace(/["\\]/g, '_');
      return reply
        .header('Content-Type', contentType)
        .header('Content-Disposition', `inline; filename="${safeName}"`)
        .send(stream);
    } catch (error) {
      this.handleError(error, 'getMedia');
    }
  }

  /** Public media URL for embedded gallery/video on public profile page (no auth). */
  @Get('public-media/:type/:fileId')
  @HttpCode(HttpStatus.OK)
  async getPublicMedia(
    @Param('organizationId') organizationId: string,
    @Param('type') type: string,
    @Param('fileId') fileId: string,
    @Res() reply: FastifyReply,
  ) {
    try {
      if (type !== 'gallery' && type !== 'video') {
        throw new BadRequestException('type must be "gallery" or "video"');
      }
      const { stream, contentType, file_name } =
        await this.companyProfileService.getMediaStreamPublic(
          organizationId,
          type as 'gallery' | 'video',
          fileId,
        );
      const safeName = (file_name ?? 'file').replace(/["\\]/g, '_');
      return reply
        .header('Content-Type', contentType)
        .header('Content-Disposition', `inline; filename="${safeName}"`)
        .send(stream);
    } catch (error) {
      this.handleError(error, 'getPublicMedia');
    }
  }
}
