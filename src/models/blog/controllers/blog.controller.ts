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
  Res,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { BlogService } from '../services/blog.service';
import { BlogImageStorageService } from '../services/blog-image-storage.service';
import { CreateBlogDto } from '../dto/create-blog.dto';
import { UpdateBlogDto } from '../dto/update-blog.dto';
import { QueryBlogDto } from '../dto/query-blog.dto';
import { PresignBlogUploadDto } from '../dto/presign-blog-upload.dto';
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

  @Post('images/presign-upload')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async presignImageUpload(@Body() dto: PresignBlogUploadDto): Promise<unknown> {
    const data = await this.blogImageStorage.presignImageUpload(dto.filename, dto.contentType);
    return SuccessHelper.createSuccessResponse(data);
  }

  @Post('videos/presign-upload')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async presignVideoUpload(@Body() dto: PresignBlogUploadDto): Promise<unknown> {
    const data = await this.blogImageStorage.presignVideoUpload(dto.filename, dto.contentType);
    return SuccessHelper.createSuccessResponse(data);
  }

  /**
   * Preserves the existing /blogs/images/:filename URL pattern.
   * Now 302-redirects to a short-TTL presigned S3 GET URL so legacy DB URLs keep working after backfill.
   */
  @Get('images/:filename')
  async serveImage(
    @Param('filename') filename: string,
    @Res() reply: FastifyReply,
  ): Promise<unknown> {
    const url = await this.blogImageStorage.getPresignedViewUrl(`blog-images/${filename}`);
    return reply.redirect(url, 302);
  }

  /**
   * Preserves the existing /blogs/videos/:filename URL pattern.
   * 302-redirects to a short-TTL presigned S3 GET URL.
   */
  @Get('videos/:filename')
  async serveVideo(
    @Param('filename') filename: string,
    @Res() reply: FastifyReply,
  ): Promise<unknown> {
    const url = await this.blogImageStorage.getPresignedViewUrl(`blog-videos/${filename}`);
    return reply.redirect(url, 302);
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
