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
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.findBySlug(slug, {
      allowDraft: !!user,
      userId: user?.userId,
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

  /** Toggle like on a blog (authenticated). Returns { liked, likeCount }. */
  @Post(':id/like')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async toggleLike(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.toggleLike(id, user.userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  /** Remove like. */
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

  /** Get comments for a blog (public). */
  @Get(':id/comments')
  @HttpCode(HttpStatus.OK)
  async getComments(@Param('id') id: string): Promise<unknown> {
    const comments = await this.blogService.getComments(id);
    return SuccessHelper.createSuccessResponse({ comments });
  }

  /** Post a comment (authenticated). */
  @Post(':id/comments')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async createComment(
    @Param('id') id: string,
    @Body() body: { content: string },
    @LoggedInUser() user: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.createComment(id, user.userId, body.content);
    return SuccessHelper.createSuccessResponse(result, 'Comment added');
  }

  @Get(':id')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('id') id: string,
    @LoggedInUser() user?: UserWithRolesInterface,
  ): Promise<unknown> {
    const result = await this.blogService.findOne(id, {
      allowDraft: !!user,
      userId: user?.userId,
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
