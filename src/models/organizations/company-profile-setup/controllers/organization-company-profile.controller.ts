import {
  Controller,
  Get,
  Put,
  Post,
  Body,
  Param,
  Query,
  Res,
  UseGuards,
  HttpCode,
  HttpStatus,
  BadRequestException,
  UnauthorizedException,
  InternalServerErrorException,
  HttpException,
  Logger,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { JwtAuthGuard } from '../../../../common/guards/jwt-auth.guard';
import { OrganizationRoleGuard } from '../../../../common/guards/organization-role.guard';
import { Roles } from '../../../../common/decorators/roles.decorator';
import { LoggedInUser } from '../../../../common/decorators/requests/logged-in-user.decorator';
import type { UserWithRolesInterface } from '../../../../common/interfaces/user-with-roles.interface';
import { SuccessHelper } from '../../../../common/helpers/responses/success.helper';
import { OrganizationCompanyProfileService } from '../services/organization-company-profile.service';
import { UpdateOrganizationCompanyProfileDto } from '../dto/update-organization-company-profile.dto';
import { PresignCompanyProfileUploadDto } from '../dto/presign-company-profile-upload.dto';
import { ConfirmCompanyProfileGalleryUploadDto } from '../dto/confirm-company-profile-gallery-upload.dto';
import { ConfirmCompanyProfileVideoUploadDto } from '../dto/confirm-company-profile-video-upload.dto';

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

  private ensureOrganizationId(organizationId: string): void {
    if (!organizationId || typeof organizationId !== 'string' || !organizationId.trim()) {
      throw new BadRequestException('Organization ID is required.');
    }
  }

  /** Public profile (no auth); for public profile page. :organizationId can be UUID or slug (URL-friendly name). */
  @Get('public')
  @HttpCode(HttpStatus.OK)
  async getPublic(@Param('organizationId') organizationId: string) {
    try {
      this.ensureOrganizationId(organizationId);
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
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const data = await this.companyProfileService.getByOrganizationId(organizationId, userId);
      return SuccessHelper.createSuccessResponse(data);
    } catch (error) {
      this.handleError(error, 'get');
    }
  }

  /** Check if a company name is available (no other org uses the same slug). */
  @Get('check-name')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async checkName(
    @Param('organizationId') organizationId: string,
    @Query('name') name: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      if (!name?.trim()) throw new BadRequestException('name query param is required');
      const result = await this.companyProfileService.checkNameAvailability(organizationId, name.trim());
      return SuccessHelper.createSuccessResponse(result);
    } catch (error) {
      this.handleError(error, 'checkName');
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
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const data = await this.companyProfileService.upsert(organizationId, dto, userId);
      return SuccessHelper.createSuccessResponse(data, 'Company profile saved successfully');
    } catch (error) {
      this.handleError(error, 'upsert');
    }
  }

  @Post('gallery/presign-upload')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async presignGalleryUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: PresignCompanyProfileUploadDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const data = await this.companyProfileService.presignGalleryUpload(
        organizationId,
        dto.filename,
        dto.contentType,
        userId,
      );
      return SuccessHelper.createSuccessResponse(data);
    } catch (error) {
      this.handleError(error, 'presignGalleryUpload');
    }
  }

  @Post('gallery')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.CREATED)
  async confirmGalleryUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: ConfirmCompanyProfileGalleryUploadDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const result = await this.companyProfileService.confirmGalleryUpload(
        organizationId,
        { key: dto.key, caption: dto.caption ?? '', category: dto.category ?? '' },
        userId,
      );
      return SuccessHelper.createSuccessResponse(result, 'Gallery image uploaded successfully');
    } catch (error) {
      this.handleError(error, 'confirmGalleryUpload');
    }
  }

  @Post('videos/presign-upload')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.OK)
  async presignVideoUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: PresignCompanyProfileUploadDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const data = await this.companyProfileService.presignVideoUpload(
        organizationId,
        dto.filename,
        dto.contentType,
        userId,
      );
      return SuccessHelper.createSuccessResponse(data);
    } catch (error) {
      this.handleError(error, 'presignVideoUpload');
    }
  }

  @Post('videos')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  @HttpCode(HttpStatus.CREATED)
  async confirmVideoUpload(
    @Param('organizationId') organizationId: string,
    @Body() dto: ConfirmCompanyProfileVideoUploadDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      const result = await this.companyProfileService.confirmVideoUpload(
        organizationId,
        {
          key: dto.key,
          title: dto.title,
          description: dto.description,
          duration: dto.duration,
          category: dto.category,
        },
        userId,
      );
      return SuccessHelper.createSuccessResponse(result, 'Video uploaded successfully');
    } catch (error) {
      this.handleError(error, 'confirmVideoUpload');
    }
  }

  /**
   * Preserves the existing /media/:type/:fileId URL pattern — now 302-redirects
   * to a short-TTL presigned S3 GET URL. <img src> / <video src> / fetch all work.
   */
  @Get('media/:type/:fileId')
  @UseGuards(JwtAuthGuard, OrganizationRoleGuard)
  @Roles('OWNER', 'HR', 'MANAGER')
  async getMedia(
    @Param('organizationId') organizationId: string,
    @Param('type') type: string,
    @Param('fileId') fileId: string,
    @Res() reply: FastifyReply,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      const userId = user?.userId;
      if (!userId) throw new UnauthorizedException('User not found');
      if (type !== 'gallery' && type !== 'video') {
        throw new BadRequestException('type must be "gallery" or "video"');
      }
      if (!fileId?.trim()) {
        throw new BadRequestException('fileId is required.');
      }
      const { url } = await this.companyProfileService.getMediaSignedUrl(
        organizationId,
        type as 'gallery' | 'video',
        fileId,
        userId,
      );
      return reply.redirect(url, 302);
    } catch (error) {
      this.handleError(error, 'getMedia');
    }
  }

  /** Public media URL for embedded gallery/video on public profile page (no auth). 302 redirect to signed URL. */
  @Get('public-media/:type/:fileId')
  async getPublicMedia(
    @Param('organizationId') organizationId: string,
    @Param('type') type: string,
    @Param('fileId') fileId: string,
    @Res() reply: FastifyReply,
  ) {
    try {
      this.ensureOrganizationId(organizationId);
      if (type !== 'gallery' && type !== 'video') {
        throw new BadRequestException('type must be "gallery" or "video"');
      }
      if (!fileId?.trim()) {
        throw new BadRequestException('fileId is required.');
      }
      const { url } = await this.companyProfileService.getMediaSignedUrlPublic(
        organizationId,
        type as 'gallery' | 'video',
        fileId,
      );
      return reply.redirect(url, 302);
    } catch (error) {
      this.handleError(error, 'getPublicMedia');
    }
  }
}
