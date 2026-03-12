import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { Blog } from '../entities/blog.entity';
import { BlogLike } from '../entities/blog-like.entity';
import { BlogComment } from '../entities/blog-comment.entity';
import { User } from '../../../authentication/entities/user.entity';
import { CreateBlogDto } from '../dto/create-blog.dto';
import { UpdateBlogDto } from '../dto/update-blog.dto';
import { QueryBlogDto } from '../dto/query-blog.dto';
import { BlogSerializer, type SerializedBlog } from '../serializers/blog.serializer';

@Injectable()
export class BlogService {
  private blogSerializer = new BlogSerializer();

  constructor(
    @InjectRepository(Blog)
    private blogRepository: Repository<Blog>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(BlogLike)
    private blogLikeRepository: Repository<BlogLike>,
    @InjectRepository(BlogComment)
    private blogCommentRepository: Repository<BlogComment>,
  ) {}

  async create(createBlogDto: CreateBlogDto, userId: string): Promise<SerializedBlog> {
    // Check if slug already exists
    const existingBlog = await this.blogRepository.findOne({
      where: { slug: createBlogDto.slug },
    });

    if (existingBlog) {
      throw new BadRequestException('A blog post with this slug already exists');
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
    const author = (await this.userRepository.findOne({ where: { id: userId } })) || undefined;
    return this.blogSerializer.serialize(saved, author);
  }

  /**
   * Find all blogs for the current user (author). Used by blogger dashboard.
   */
  async findMyBlogs(
    userId: string,
    page: number = 1,
    limit: number = 50,
  ): Promise<{ data: SerializedBlog[]; total: number; page: number; limit: number }> {
    const skip = (page - 1) * limit;
    const queryBuilder = this.blogRepository
      .createQueryBuilder('blog')
      .where('blog.author_id = :userId', { userId })
      .orderBy('blog.created_at', 'DESC')
      .skip(skip)
      .take(limit);

    const [blogs, total] = await queryBuilder.getManyAndCount();
    const authorsMap = await this.getAuthorsMap(blogs.map((b) => b.author_id).filter(Boolean) as string[]);
    let countMap: Map<string, { likeCount: number; commentCount: number }>;
    try {
      countMap = await this.getLikeAndCommentCountMap(blogs.map((b) => b.id));
    } catch {
      countMap = new Map();
    }
    return {
      data: this.blogSerializer.serializeMany(
        blogs as (Blog & { author?: User })[],
        authorsMap,
        countMap,
      ),
      total,
      page,
      limit,
    };
  }

  async findAll(queryDto: QueryBlogDto): Promise<{
    data: SerializedBlog[];
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
    const authorsMap = await this.getAuthorsMap(blogs.map((b) => b.author_id).filter(Boolean) as string[]);
    let countMap: Map<string, { likeCount: number; commentCount: number }>;
    try {
      countMap = await this.getLikeAndCommentCountMap(blogs.map((b) => b.id));
    } catch {
      countMap = new Map();
    }
    return {
      data: this.blogSerializer.serializeMany(
        blogs as (Blog & { author?: User })[],
        authorsMap,
        countMap,
      ),
      total,
      page,
      limit,
    };
  }

  /**
   * Load users by ids for author names. Uses only id/firstName/lastName so it works when
   * displayName column is missing on production (serializer falls back to firstName + lastName).
   */
  private async getAuthorsMap(authorIds: string[]): Promise<Map<string, User>> {
    if (authorIds.length === 0) return new Map();
    const unique = [...new Set(authorIds)];
    try {
      const users = await this.userRepository.find({
        where: { id: In(unique) },
        select: ['id', 'firstName', 'lastName'],
      });
      return new Map(users.map((u) => [u.id, u]));
    } catch {
      return new Map();
    }
  }

  async findOne(
    id: string,
    options?: { allowDraft?: boolean; userId?: string },
  ): Promise<SerializedBlog> {
    const blog = await this.blogRepository.findOne({
      where: { id },
      relations: ['author'],
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    if (!options?.allowDraft && !blog.is_published) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    let likeCount = 0;
    let commentCount = 0;
    let userHasLiked: boolean | undefined;
    try {
      [likeCount, commentCount, userHasLiked] = await Promise.all([
        this.getLikeCount(id),
        this.getCommentCount(id),
        options?.userId ? this.userHasLiked(id, options.userId) : Promise.resolve(undefined),
      ]);
    } catch {
      // Tables may not exist on older DBs; use zeros
    }
    return this.blogSerializer.serialize(blog, (blog as Blog & { author?: User }).author, {
      likeCount,
      commentCount,
      userHasLiked,
    });
  }

  async findBySlug(
    slug: string,
    options?: { allowDraft?: boolean; userId?: string },
  ): Promise<SerializedBlog> {
    const blog = await this.blogRepository.findOne({
      where: { slug },
      relations: ['author'],
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with slug "${slug}" not found`);
    }

    if (!options?.allowDraft && !blog.is_published) {
      throw new NotFoundException(`Blog post with slug "${slug}" not found`);
    }

    let likeCount = 0;
    let commentCount = 0;
    let userHasLiked: boolean | undefined;
    try {
      [likeCount, commentCount, userHasLiked] = await Promise.all([
        this.getLikeCount(blog.id),
        this.getCommentCount(blog.id),
        options?.userId ? this.userHasLiked(blog.id, options.userId) : Promise.resolve(undefined),
      ]);
    } catch {
      // Tables may not exist on older DBs; use zeros
    }
    return this.blogSerializer.serialize(blog, (blog as Blog & { author?: User }).author, {
      likeCount,
      commentCount,
      userHasLiked,
    });
  }

  /** Get like and comment counts for multiple blogs (for list responses). */
  private async getLikeAndCommentCountMap(
    blogIds: string[],
  ): Promise<Map<string, { likeCount: number; commentCount: number }>> {
    if (blogIds.length === 0) return new Map();
    const [likeRows, commentRows] = await Promise.all([
      this.blogLikeRepository
        .createQueryBuilder('l')
        .select('l.blog_id', 'blog_id')
        .addSelect('COUNT(*)', 'count')
        .where('l.blog_id IN (:...ids)', { ids: blogIds })
        .groupBy('l.blog_id')
        .getRawMany<{ blog_id: string; count: string }>(),
      this.blogCommentRepository
        .createQueryBuilder('c')
        .select('c.blog_id', 'blog_id')
        .addSelect('COUNT(*)', 'count')
        .where('c.blog_id IN (:...ids)', { ids: blogIds })
        .groupBy('c.blog_id')
        .getRawMany<{ blog_id: string; count: string }>(),
    ]);
    const map = new Map<string, { likeCount: number; commentCount: number }>();
    for (const id of blogIds) {
      map.set(id, { likeCount: 0, commentCount: 0 });
    }
    for (const row of likeRows) {
      const cur = map.get(row.blog_id);
      if (cur) cur.likeCount = parseInt(row.count, 10);
    }
    for (const row of commentRows) {
      const cur = map.get(row.blog_id);
      if (cur) cur.commentCount = parseInt(row.count, 10);
    }
    return map;
  }

  private async getLikeCount(blogId: string): Promise<number> {
    return this.blogLikeRepository.count({ where: { blog_id: blogId } });
  }

  private async getCommentCount(blogId: string): Promise<number> {
    return this.blogCommentRepository.count({ where: { blog_id: blogId } });
  }

  private async userHasLiked(blogId: string, userId: string): Promise<boolean> {
    const one = await this.blogLikeRepository.findOne({
      where: { blog_id: blogId, user_id: userId },
    });
    return !!one;
  }

  async toggleLike(blogId: string, userId: string): Promise<{ liked: boolean; likeCount: number }> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const existing = await this.blogLikeRepository.findOne({
      where: { blog_id: blogId, user_id: userId },
    });
    if (existing) {
      await this.blogLikeRepository.remove(existing);
      const likeCount = await this.getLikeCount(blogId);
      return { liked: false, likeCount };
    }
    await this.blogLikeRepository.save({
      blog_id: blogId,
      user_id: userId,
    });
    const likeCount = await this.getLikeCount(blogId);
    return { liked: true, likeCount };
  }

  async removeLike(blogId: string, userId: string): Promise<{ likeCount: number }> {
    const existing = await this.blogLikeRepository.findOne({
      where: { blog_id: blogId, user_id: userId },
    });
    if (existing) await this.blogLikeRepository.remove(existing);
    const likeCount = await this.getLikeCount(blogId);
    return { likeCount };
  }

  async createComment(
    blogId: string,
    userId: string,
    content: string,
  ): Promise<{ id: string; content: string; created_at: Date; author_name: string }> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'firstName', 'lastName', 'displayName'],
    });
    if (!user) throw new NotFoundException('User not found');
    const trimmed = (content || '').trim();
    if (!trimmed) throw new BadRequestException('Comment content is required');
    const comment = await this.blogCommentRepository.save({
      blog_id: blogId,
      user_id: userId,
      content: trimmed,
    });
    const authorName =
      user.displayName?.trim() || `${user.firstName} ${user.lastName}`.trim() || 'Anonymous';
    return {
      id: comment.id,
      content: comment.content,
      created_at: comment.created_at,
      author_name: authorName,
    };
  }

  async getComments(
    blogId: string,
  ): Promise<Array<{ id: string; content: string; created_at: Date; author_name: string }>> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const comments = await this.blogCommentRepository.find({
      where: { blog_id: blogId },
      relations: ['user'],
      order: { created_at: 'ASC' },
    });
    return comments.map((c) => {
      const u = c.user as User | undefined;
      const authorName = u
        ? u.displayName?.trim() || `${u.firstName} ${u.lastName}`.trim() || 'Anonymous'
        : 'Anonymous';
      return {
        id: c.id,
        content: c.content,
        created_at: c.created_at,
        author_name: authorName,
      };
    });
  }

  async update(id: string, updateBlogDto: UpdateBlogDto, _userId: string): Promise<SerializedBlog> {
    const blog = await this.blogRepository.findOne({
      where: { id },
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    // Check if slug is being updated and if it already exists
    if (updateBlogDto.slug && updateBlogDto.slug !== blog.slug) {
      const existingBlog = await this.blogRepository.findOne({
        where: { slug: updateBlogDto.slug },
      });

      if (existingBlog) {
        throw new BadRequestException('A blog post with this slug already exists');
      }
    }

    // Handle publishing
    const updateData: Partial<Blog> & { published_at?: Date } = { ...updateBlogDto };
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

  async remove(id: string, _userId: string): Promise<void> {
    const blog = await this.blogRepository.findOne({
      where: { id },
    });

    if (!blog) {
      throw new NotFoundException(`Blog post with ID ${id} not found`);
    }

    await this.blogRepository.remove(blog);
  }
}
