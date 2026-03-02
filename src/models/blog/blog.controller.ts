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
import { BlogService } from './blog.service';
import { BlogImageStorageService } from './services/blog-image-storage.service';
import { CreateBlogDto } from './dto/create-blog.dto';
import { UpdateBlogDto } from './dto/update-blog.dto';
import { QueryBlogDto } from './dto/query-blog.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from '../../common/guards/optional-jwt-auth.guard';
import { LoggedInUser } from '../../common/decorators/requests/logged-in-user.decorator';
import { SuccessHelper } from '../../common/helpers/responses/success.helper';
import type { UserWithRolesInterface } from '../../common/interfaces/user-with-roles.interface';

@Controller('v1/api/blogs')
export class BlogController {
  constructor(
    private readonly blogService: BlogService,
    private readonly blogImageStorage: BlogImageStorageService,
  ) {}

  /**
   * Upload a blog featured image
   */
  @Post('images/upload')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async uploadImage(@Req() request: FastifyRequest) {
    const multipartRequest = request as FastifyRequest & {
      file: () => Promise<{ filename: string; toBuffer: () => Promise<Buffer> } | undefined>;
    };
    const data = await multipartRequest.file();
    if (!data) throw new BadRequestException('No file uploaded');
    const buffer = await data.toBuffer();
    const result = await this.blogImageStorage.saveBlogImage(buffer, data.filename);
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
  ) {
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
  ) {
    const result = await this.blogService.create(
      createBlogDto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Blog post created successfully',
    );
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
  ) {
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
  ) {
    const result = await this.blogService.findBySlug(slug, {
      allowDraft: !!user,
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
  ) {
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

  @Get(':id')
  @UseGuards(OptionalJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async findOne(
    @Param('id') id: string,
    @LoggedInUser() user?: UserWithRolesInterface,
  ) {
    const result = await this.blogService.findOne(id, {
      allowDraft: !!user,
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
  ) {
    const result = await this.blogService.update(
      id,
      updateBlogDto,
      user.userId,
    );
    return SuccessHelper.createSuccessResponse(
      result,
      'Blog post updated successfully',
    );
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async remove(
    @Param('id') id: string,
    @LoggedInUser() user: UserWithRolesInterface,
  ) {
    await this.blogService.remove(id, user.userId);
    return SuccessHelper.createSuccessResponse(
      null,
      'Blog post deleted successfully',
    );
  }
}
