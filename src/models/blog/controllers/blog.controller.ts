import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
  Res,
  NotFoundException,
} from '@nestjs/common';
import type { FastifyRequest, FastifyReply } from 'fastify';
import * as fs from 'fs';
import * as path from 'path';
import { BlogService } from '../services/blog.service';
import { BlogImageStorageService } from '../services/blog-image-storage.service';
import { CreateBlogDto } from '../dto/create-blog.dto';
import { UpdateBlogDto } from '../dto/update-blog.dto';
import { QueryBlogDto } from '../dto/query-blog.dto';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from '../../../common/guards/optional-jwt-auth.guard';
import { LoggedInUser } from '../../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';

@Controller('v1/api/blogs')
export class BlogController {
  constructor(
    private readonly blogService: BlogService,
    private readonly blogImageStorage: BlogImageStorageService,
  ) {}

  /**
   * Upload a blog featured image.
   * With Fastify multipart attachFieldsToBody: true, the file is on request.body, not request.file().
   */
  @Post('images/upload')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async uploadImage(@Req() request: FastifyRequest): Promise<unknown> {
    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string; _buf?: Buffer }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string; _buf?: Buffer }>
      >;
    };

    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Content-Type must be multipart/form-data');
    }

    const body = multipartRequest.body;
    const filePart = body?.file;
    const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

    if (!singleFile?.filename) {
      throw new BadRequestException('No file uploaded. Send a field named "file".');
    }

    const buffer =
      singleFile._buf != null
        ? singleFile._buf
        : typeof singleFile.toBuffer === 'function'
          ? await singleFile.toBuffer()
          : null;
    if (!buffer || !Buffer.isBuffer(buffer)) {
      throw new BadRequestException('Could not read file data');
    }

    const result = await this.blogImageStorage.saveBlogImage(buffer, singleFile.filename);
    return SuccessHelper.createSuccessResponse(result, 'Image uploaded successfully');
  }

  /**
   * Upload a main/hero video for a blog (multipart field "file").
   */
  @Post('videos/upload')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async uploadVideo(@Req() request: FastifyRequest): Promise<unknown> {
    const multipartRequest = request as FastifyRequest & {
      isMultipart?: () => boolean;
      body?: Record<
        string,
        | { value?: string; toBuffer?: () => Promise<Buffer>; filename?: string; _buf?: Buffer }
        | Array<{ toBuffer?: () => Promise<Buffer>; filename?: string; _buf?: Buffer }>
      >;
    };

    if (!multipartRequest.isMultipart?.()) {
      throw new BadRequestException('Content-Type must be multipart/form-data');
    }

    const body = multipartRequest.body;
    const filePart = body?.file;
    const singleFile = Array.isArray(filePart) ? filePart[0] : filePart;

    if (!singleFile?.filename) {
      throw new BadRequestException('No file uploaded. Send a field named "file".');
    }

    const buffer =
      singleFile._buf != null
        ? singleFile._buf
        : typeof singleFile.toBuffer === 'function'
          ? await singleFile.toBuffer()
          : null;
    if (!buffer || !Buffer.isBuffer(buffer)) {
      throw new BadRequestException('Could not read file data');
    }

    const result = await this.blogImageStorage.saveBlogVideo(buffer, singleFile.filename);
    return SuccessHelper.createSuccessResponse(result, 'Video uploaded successfully');
  }

  /**
   * Serve a blog image by filename
   */
  @Get('images/:filename')
  @HttpCode(HttpStatus.OK)
  async serveImage(
    @Param('filename') filename: string,
    @Res() reply: FastifyReply,
  ): Promise<unknown> {
    const filePath = this.blogImageStorage.getLocalFilePath(filename);
    if (!filePath) throw new NotFoundException('File not found');
    const ext = path.extname(filename).toLowerCase();
    const contentType =
      {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.svg': 'image/svg+xml',
      }[ext] || 'application/octet-stream';
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${filename}"`)
      .send(fs.createReadStream(filePath));
  }

  /**
   * Serve an uploaded blog video by stored filename (local storage only; S3 uses direct object URL).
   */
  @Get('videos/:filename')
  @HttpCode(HttpStatus.OK)
  async serveVideo(
    @Param('filename') filename: string,
    @Res() reply: FastifyReply,
  ): Promise<unknown> {
    const filePath = this.blogImageStorage.getLocalVideoFilePath(filename);
    if (!filePath) throw new NotFoundException('File not found');
    const ext = path.extname(filename).toLowerCase();
    const contentType =
      {
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.mov': 'video/quicktime',
        '.mpeg': 'video/mpeg',
        '.mpg': 'video/mpeg',
        '.ogv': 'video/ogg',
        '.m4v': 'video/x-m4v',
      }[ext] || 'application/octet-stream';
    return reply
      .header('Content-Type', contentType)
      .header('Content-Disposition', `inline; filename="${filename}"`)
      .send(fs.createReadStream(filePath));
  }

  @Post()
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() createBlogDto: CreateBlogDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.create(createBlogDto, user.userId);
    return SuccessHelper.createSuccessResponse(result, 'Blog post created successfully');
  }

  /**
   * List blogs. Public: when not logged in, only published blogs are returned.
   * Authenticated users can pass is_published=false to see drafts (e.g. their own).
   */
  @Get()
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Query() queryDto: QueryBlogDto,
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    if (!user) {
      queryDto.is_published = true;
    }
    const result = await this.blogService.findAll(queryDto);
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  @Get('slug/:slug')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async findBySlug(
    @Param('slug') slug: string,
    @Query('guestId') guestId: string | undefined,
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.findBySlug(slug, {
      allowDraft: !!user,
      userId: user?.userId,
      guestId: guestId?.trim() || undefined,
    });
    return SuccessHelper.createSuccessResponse(result);
  }

  /**
   * Get current user's (blogger's) blogs for dashboard. Must be before :id route.
   */
  @Get('my-blogs')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMyBlogs(
    @LoggedInUser() user: UserWithRolesInterface,
    @Query('page') page?: number,
    @Query('limit') limit?: number,
  ): Promise<unknown> {
    const result = await this.blogService.findMyBlogs(
      user.userId,
      page ? Number(page) : 1,
      limit ? Number(limit) : 50,
    );
    return SuccessHelper.createPaginatedResponse(
      result.data,
      result.total,
      result.page,
      result.limit,
    );
  }

  /** Admin only: list all blog comments for moderation. */
  @Get('admin/comments')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getAllCommentsForAdmin(@LoggedInUser() user: UserWithRolesInterface): Promise<unknown> {
    const comments = await this.blogService.getAllCommentsForAdmin(user.roles);
    return SuccessHelper.createSuccessResponse({ comments });
  }

  /** Blogger: list all comments on my blogs for moderation. */
  @Get('my-blogs/comments')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMyBlogsComments(@LoggedInUser() user: UserWithRolesInterface): Promise<unknown> {
    const comments = await this.blogService.getMyBlogsComments(user.userId);
    return SuccessHelper.createSuccessResponse({ comments });
  }

  /**
   * Toggle like. Only the same user or guest who liked can unlike.
   * - When authenticated: use only userId (ignore guestId); toggles/removes only this user's like.
   * - When not authenticated: require guestId in body; toggles/removes only this guest's like.
   */
  @Post(':id/like')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async toggleLike(
    @Param('id') id: string,
    @Body() body: { guestId?: string },
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.toggleLike(id, {
      userId: user?.userId,
      guestId: user ? undefined : body?.guestId?.trim() || undefined,
    });
    return SuccessHelper.createSuccessResponse(result);
  }

  /**
   * Remove like (authenticated only). Removes only this user's like; no one else's.
   */
  @Delete(':id/like')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async removeLike(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.removeLike(id, user.userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  /** Get comments for a blog. Public: only approved. ?moderation=1 with auth (blogger/admin): all with status. */
  @Get(':id/comments')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getComments(
    @Param('id') id: string,
    @Query('moderation') moderation: string | undefined,
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    if (moderation === '1' && user) {
      const comments = await this.blogService.getCommentsForModeration(id, user.userId, user.roles);
      return SuccessHelper.createSuccessResponse({ comments });
    }
    const comments = await this.blogService.getComments(id);
    return SuccessHelper.createSuccessResponse({ comments });
  }

  /** Post a comment (logged-in users only). New comments are pending until blogger/admin approve. */
  @Post(':id/comments')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async createComment(
    @Param('id') id: string,
    @Body() body: { content?: string; comment?: string; text?: string },
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const content =
      [body.content, body.comment, body.text]
        .find((v) => typeof v === 'string' && v.trim().length > 0)
        ?.trim() ?? '';
    const result = await this.blogService.createComment(id, content, user.userId);
    return SuccessHelper.createSuccessResponse(result, 'Comment submitted for approval');
  }

  /** Approve a comment (blog author or admin only). */
  @Patch(':id/comments/:commentId/approve')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async approveComment(
    @Param('id') id: string,
    @Param('commentId') commentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.approveComment(id, commentId, user.userId, user.roles);
    return SuccessHelper.createSuccessResponse(result, 'Comment approved');
  }

  /** Delete a comment (blog author or admin only). */
  @Delete(':id/comments/:commentId')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async deleteComment(
    @Param('id') id: string,
    @Param('commentId') commentId: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    await this.blogService.deleteComment(id, commentId, user.userId, user.roles);
    return SuccessHelper.createSuccessResponse(null, 'Comment deleted');
  }

  @Get(':id')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('id') id: string,
    @Query('guestId') guestId: string | undefined,
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.findOne(id, {
      allowDraft: !!user,
      userId: user?.userId,
      guestId: guestId?.trim() || undefined,
    });
    return SuccessHelper.createSuccessResponse(result);
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async update(
    @Param('id') id: string,
    @Body() updateBlogDto: UpdateBlogDto,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.update(id, updateBlogDto, user.userId);
    return SuccessHelper.createSuccessResponse(result, 'Blog post updated successfully');
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    await this.blogService.remove(id, user.userId);
    return SuccessHelper.createSuccessResponse(null, 'Blog post deleted successfully');
  }
}
