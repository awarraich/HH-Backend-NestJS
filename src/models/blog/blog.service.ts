import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { Blog } from './entities/blog.entity';
import { User } from '../../authentication/entities/user.entity';
import { CreateBlogDto } from './dto/create-blog.dto';
import { UpdateBlogDto } from './dto/update-blog.dto';
import { QueryBlogDto } from './dto/query-blog.dto';
import { BlogSerializer } from './serializers/blog.serializer';

@Injectable()
export class BlogService {
  private blogSerializer = new BlogSerializer();

  constructor(
    @InjectRepository(Blog)
    private blogRepository: Repository<Blog>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async create(
    createBlogDto: CreateBlogDto,
    userId: string,
  ): Promise<any> {
    // Check if slug already exists
    const existingBlog = await this.blogRepository.findOne({
      where: { slug: createBlogDto.slug },
    });

    if (existingBlog) {
      throw new BadRequestException(
        'A blog post with this slug already exists',
      );
    }

    const blogData = {
      ...createBlogDto,
      author_id: userId,
      is_published: createBlogDto.is_published ?? false,
      published_at: createBlogDto.is_published ? new Date() : undefined,
    };

    const blog = this.blogRepository.create(blogData);
    const saved = await this.blogRepository.save(blog);
    
    // Fetch author for response
    const author = await this.userRepository.findOne({ where: { id: userId } }) || undefined;
    return this.blogSerializer.serialize(saved, author);
  }

  async findAll(queryDto: QueryBlogDto): Promise<{
    data: any[];
    total: number;
    page: number;
    limit: number;
  }> {
    const { is_published, category, search, page = 1, limit = 20 } = queryDto;
    const skip = (page - 1) * limit;

    const queryBuilder = this.blogRepository.createQueryBuilder('blog');

    if (is_published !== undefined) {
      queryBuilder.andWhere('blog.is_published = :is_published', {
        is_published,
      });
    }

    if (category) {
      queryBuilder.andWhere('blog.category = :category', { category });
    }

    if (search) {
      queryBuilder.andWhere(
        '(blog.title ILIKE :search OR blog.content ILIKE :search OR blog.excerpt ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    queryBuilder.orderBy('blog.created_at', 'DESC');
    queryBuilder.skip(skip).take(limit);

    const [blogs, total] = await queryBuilder.getManyAndCount();

    return {
      data: this.blogSerializer.serializeMany(blogs),
      total,
      page,
      limit,
    };
  }

  async findOne(id: string): Promise<any> {
    const blog = await this.blogRepository.findOne({
      where: { id },
      relations: ['author'],
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    return this.blogSerializer.serialize(blog);
  }

  async findBySlug(slug: string): Promise<any> {
    const blog = await this.blogRepository.findOne({
      where: { slug },
      relations: ['author'],
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with slug "${slug}" not found`);
    }

    return this.blogSerializer.serialize(blog);
  }

  async update(
    id: string,
    updateBlogDto: UpdateBlogDto,
    userId: string,
  ): Promise<any> {
    const blog = await this.blogRepository.findOne({
      where: { id },
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    // Check if slug is being updated and if it already exists
    if (
      updateBlogDto.slug &&
      updateBlogDto.slug !== blog.slug
    ) {
      const existingBlog = await this.blogRepository.findOne({
        where: { slug: updateBlogDto.slug },
      });

      if (existingBlog) {
        throw new BadRequestException(
          'A blog post with this slug already exists',
        );
      }
    }

    // Handle publishing
    const updateData: any = { ...updateBlogDto };
    if (updateBlogDto.is_published !== undefined) {
      if (updateBlogDto.is_published && !blog.is_published) {
        updateData.published_at = new Date();
      } else if (!updateBlogDto.is_published) {
        updateData.published_at = undefined;
      }
    }

    Object.assign(blog, updateData);
    const updated = await this.blogRepository.save(blog);

    return this.blogSerializer.serialize(updated);
  }

  async remove(id: string, userId: string): Promise<void> {
    const blog = await this.blogRepository.findOne({
      where: { id },
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    await this.blogRepository.remove(blog);
  }
}
