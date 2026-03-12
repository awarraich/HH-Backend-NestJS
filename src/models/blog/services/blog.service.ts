import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
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
  private readonly logger = new Logger(BlogService.name);
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
    const authorsMap = await this.getAuthorsMap(blogs.map((b) => b.author_id).filter(Boolean));
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
    const authorsMap = await this.getAuthorsMap(blogs.map((b) => b.author_id).filter(Boolean));
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
    options?: { allowDraft?: boolean; userId?: string; guestId?: string },
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
      const [count, commentCountRes, userLiked, guestLiked] = await Promise.all([
        this.getLikeCount(id),
        this.getCommentCount(id),
        options?.userId ? this.userHasLiked(id, options.userId) : Promise.resolve(undefined),
        options?.guestId ? this.guestHasLiked(id, options.guestId) : Promise.resolve(undefined),
      ]);
      likeCount = count;
      commentCount = commentCountRes;
      userHasLiked = userLiked ?? guestLiked;
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
    options?: { allowDraft?: boolean; userId?: string; guestId?: string },
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
      const [count, commentCountRes, userLiked, guestLiked] = await Promise.all([
        this.getLikeCount(blog.id),
        this.getCommentCount(blog.id),
        options?.userId ? this.userHasLiked(blog.id, options.userId) : Promise.resolve(undefined),
        options?.guestId
          ? this.guestHasLiked(blog.id, options.guestId)
          : Promise.resolve(undefined),
      ]);
      likeCount = count;
      commentCount = commentCountRes;
      userHasLiked = userLiked ?? guestLiked;
    } catch (err) {
      this.logger.warn(
        `Blog findBySlug: like/comment count failed for blog ${blog.id}, using zeros`,
        err instanceof Error ? err.message : String(err),
      );
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
        .andWhere("c.status = 'approved'")
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
    const row = await this.blogLikeRepository
      .createQueryBuilder('l')
      .select('COUNT(*)', 'c')
      .where('l.blog_id = :blogId', { blogId })
      .getRawOne<{ c: string }>();
    return row ? parseInt(row.c, 10) || 0 : 0;
  }

  private async getCommentCount(blogId: string): Promise<number> {
    return this.blogCommentRepository.count({
      where: { blog_id: blogId, status: 'approved' },
    });
  }

  private static readonly GUEST_ID_REGEX = /^[a-zA-Z0-9_-]{8,64}$/;

  private async userHasLiked(blogId: string, userId: string): Promise<boolean> {
    const one = await this.blogLikeRepository.findOne({
      where: { blog_id: blogId, user_id: userId },
    });
    return !!one;
  }

  private async guestHasLiked(blogId: string, guestId: string): Promise<boolean> {
    try {
      const one = await this.blogLikeRepository.findOne({
        where: { blog_id: blogId, guest_id: guestId },
      });
      return !!one;
    } catch {
      return false;
    }
  }

  async toggleLike(
    blogId: string,
    options: { userId?: string; guestId?: string },
  ): Promise<{ liked: boolean; likeCount: number }> {
    const { userId, guestId } = options;
    if (userId) {
      return this.toggleLikeForUser(blogId, userId);
    }
    if (guestId) {
      if (!BlogService.GUEST_ID_REGEX.test(guestId)) {
        throw new BadRequestException('Invalid guest ID format');
      }
      try {
        return await this.toggleLikeForGuest(blogId, guestId);
      } catch {
        throw new BadRequestException('Unable to like as guest. Please try again or log in.');
      }
    }
    throw new BadRequestException('Either log in or provide a guest ID to like');
  }

  private async toggleLikeForUser(
    blogId: string,
    userId: string,
  ): Promise<{ liked: boolean; likeCount: number }> {
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
    await this.blogLikeRepository.insert({
      blog_id: blogId,
      user_id: userId,
    });
    const likeCount = await this.getLikeCount(blogId);
    return { liked: true, likeCount };
  }

  private async toggleLikeForGuest(
    blogId: string,
    guestId: string,
  ): Promise<{ liked: boolean; likeCount: number }> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const existing = await this.blogLikeRepository.findOne({
      where: { blog_id: blogId, guest_id: guestId },
    });
    if (existing) {
      await this.blogLikeRepository.remove(existing);
      const likeCount = await this.getLikeCount(blogId);
      return { liked: false, likeCount };
    }
    await this.blogLikeRepository.save({
      blog_id: blogId,
      user_id: null,
      guest_id: guestId,
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

  /** Only logged-in users can comment; new comments are pending until blogger/admin approve. */
  async createComment(
    blogId: string,
    content: string,
    userId: string,
  ): Promise<{
    id: string;
    content: string;
    created_at: Date;
    author_name: string;
    status: string;
  }> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const trimmed = (content || '').trim();
    if (!trimmed) throw new BadRequestException('Comment content is required');
    if (trimmed.length > 5000) throw new BadRequestException('Comment is too long');

    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'firstName', 'lastName'],
    });
    if (!user) throw new NotFoundException('User not found');

    const comment = await this.blogCommentRepository.save({
      blog_id: blogId,
      user_id: userId,
      content: trimmed,
      status: 'pending',
    });
    const authorName = `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim() || 'Anonymous';
    return {
      id: comment.id,
      content: comment.content,
      created_at: comment.created_at,
      author_name: authorName,
      status: comment.status,
    };
  }

  /** Public list: only approved comments. */
  async getComments(
    blogId: string,
  ): Promise<Array<{ id: string; content: string; created_at: Date; author_name: string }>> {
    try {
      const blog = await this.blogRepository.findOne({ where: { id: blogId } });
      if (!blog) throw new NotFoundException('Blog not found');
      const comments = await this.blogCommentRepository.find({
        where: { blog_id: blogId, status: 'approved' },
        relations: ['user'],
        order: { created_at: 'ASC' },
      });
      return comments.map((c) => {
        const u = c.user as User | undefined;
        const authorName = u
          ? (u.displayName && String(u.displayName).trim()) ||
            `${u.firstName ?? ''} ${u.lastName ?? ''}`.trim() ||
            'Anonymous'
          : (c.guest_name && String(c.guest_name).trim()) || 'Guest';
        return {
          id: c.id,
          content: c.content,
          created_at: c.created_at,
          author_name: authorName,
        };
      });
    } catch (err) {
      if (err instanceof NotFoundException) throw err;
      return [];
    }
  }

  /** For blogger/admin: all comments with status. Caller must ensure user is blog author or ADMIN. */
  async getCommentsForModeration(
    blogId: string,
    userId: string,
    userRoles: string[],
  ): Promise<
    Array<{ id: string; content: string; created_at: Date; author_name: string; status: string }>
  > {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const isAdmin = userRoles.some((r) => r.toUpperCase() === 'ADMIN');
    const isAuthor = blog.author_id === userId;
    if (!isAdmin && !isAuthor) {
      throw new BadRequestException('Only the blog author or an admin can moderate comments');
    }
    const comments = await this.blogCommentRepository.find({
      where: { blog_id: blogId },
      relations: ['user'],
      order: { created_at: 'ASC' },
    });
    return comments.map((c) => {
      const u = c.user as User | undefined;
      const authorName = u
        ? (u.displayName && String(u.displayName).trim()) ||
          `${u.firstName ?? ''} ${u.lastName ?? ''}`.trim() ||
          'Anonymous'
        : (c.guest_name && String(c.guest_name).trim()) || 'Guest';
      return {
        id: c.id,
        content: c.content,
        created_at: c.created_at,
        author_name: authorName,
        status: c.status ?? 'pending',
      };
    });
  }

  async approveComment(
    blogId: string,
    commentId: string,
    userId: string,
    userRoles: string[],
  ): Promise<{ id: string; status: string }> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const isAdmin = userRoles.some((r) => r.toUpperCase() === 'ADMIN');
    const isAuthor = blog.author_id === userId;
    if (!isAdmin && !isAuthor) {
      throw new BadRequestException('Only the blog author or an admin can approve comments');
    }
    const comment = await this.blogCommentRepository.findOne({
      where: { id: commentId, blog_id: blogId },
    });
    if (!comment) throw new NotFoundException('Comment not found');
    comment.status = 'approved';
    await this.blogCommentRepository.save(comment);
    return { id: comment.id, status: comment.status };
  }

  async deleteComment(
    blogId: string,
    commentId: string,
    userId: string,
    userRoles: string[],
  ): Promise<void> {
    const blog = await this.blogRepository.findOne({ where: { id: blogId } });
    if (!blog) throw new NotFoundException('Blog not found');
    const isAdmin = userRoles.some((r) => r.toUpperCase() === 'ADMIN');
    const isAuthor = blog.author_id === userId;
    if (!isAdmin && !isAuthor) {
      throw new BadRequestException('Only the blog author or an admin can delete comments');
    }
    const comment = await this.blogCommentRepository.findOne({
      where: { id: commentId, blog_id: blogId },
    });
    if (!comment) throw new NotFoundException('Comment not found');
    await this.blogCommentRepository.remove(comment);
  }

  /** Admin only: all comments across all blogs for moderation UI. */
  async getAllCommentsForAdmin(userRoles: string[]): Promise<
    Array<{
      id: string;
      blog_id: string;
      blog_title: string;
      blog_slug: string;
      content: string;
      author_name: string;
      status: string;
      created_at: Date;
    }>
  > {
    const isAdmin = userRoles.some((r) => r.toUpperCase() === 'ADMIN');
    if (!isAdmin) {
      throw new BadRequestException('Only admins can list all blog comments');
    }
    const comments = await this.blogCommentRepository.find({
      relations: ['blog', 'user'],
      order: { created_at: 'DESC' },
    });
    return comments.map((c) => {
      const blog = c.blog as Blog | undefined;
      const u = c.user as User | undefined;
      const authorName = u
        ? (u.displayName && String(u.displayName).trim()) ||
          `${u.firstName ?? ''} ${u.lastName ?? ''}`.trim() ||
          'Anonymous'
        : (c.guest_name && String(c.guest_name).trim()) || 'Guest';
      return {
        id: c.id,
        blog_id: c.blog_id,
        blog_title: blog?.title ?? '',
        blog_slug: blog?.slug ?? '',
        content: c.content,
        author_name: authorName,
        status: c.status ?? 'pending',
        created_at: c.created_at,
      };
    });
  }

  /** Blogger: all comments on blogs authored by userId (for moderation UI). */
  async getMyBlogsComments(userId: string): Promise<
    Array<{
      id: string;
      blog_id: string;
      blog_title: string;
      blog_slug: string;
      content: string;
      author_name: string;
      status: string;
      created_at: Date;
    }>
  > {
    const comments = await this.blogCommentRepository
      .createQueryBuilder('c')
      .innerJoinAndSelect('c.blog', 'blog')
      .where('blog.author_id = :userId', { userId })
      .leftJoinAndSelect('c.user', 'user')
      .orderBy('c.created_at', 'DESC')
      .getMany();
    return comments.map((c) => {
      const blog = c.blog as Blog | undefined;
      const u = c.user as User | undefined;
      const authorName = u
        ? (u.displayName && String(u.displayName).trim()) ||
          `${u.firstName ?? ''} ${u.lastName ?? ''}`.trim() ||
          'Anonymous'
        : (c.guest_name && String(c.guest_name).trim()) || 'Guest';
      return {
        id: c.id,
        blog_id: c.blog_id,
        blog_title: blog?.title ?? '',
        blog_slug: blog?.slug ?? '',
        content: c.content,
        author_name: authorName,
        status: c.status ?? 'pending',
        created_at: c.created_at,
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
