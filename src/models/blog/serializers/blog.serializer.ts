import { Blog } from '../entities/blog.entity';
import { User } from '../../../authentication/entities/user.entity';

export interface SerializedBlog {
  id: string;
  title: string;
  excerpt: string;
  short_description: string;
  author: string;
  authorRole: string;
  date: string;
  readTime: string;
  category: string;
  category_name: string;
  image: string;
  likes: number;
  comments: number;
  user_has_liked?: boolean;
  slug: string;
  content: string;
  author_id: string;
  is_published: boolean;
  status: string;
  published_at: Date | null;
  tags: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface SerializeOptions {
  likeCount?: number;
  commentCount?: number;
  userHasLiked?: boolean;
}

export class BlogSerializer {
  // Calculate read time based on content (avg 200 words per minute)
  private calculateReadTime(content: string): string {
    if (!content) return '1 min read';
    const words = content.trim().split(/\s+/).length;
    const minutes = Math.ceil(words / 200);
    return `${minutes} min read`;
  }

  serialize(blog: Blog, author?: User, options?: SerializeOptions): SerializedBlog {
    // Dashboard expects status: approved | pending | rejected | draft; backend has is_published only
    const status = blog.is_published ? 'approved' : 'draft';
    return {
      id: blog.id,
      title: blog.title,
      excerpt: blog.excerpt,
      short_description: blog.excerpt ?? '', // alias for blogger dashboard
      author: author
        ? author.displayName?.trim() ||
          `${author.firstName} ${author.lastName}`.trim() ||
          'Unknown Author'
        : 'Unknown Author',
      authorRole: 'Healthcare Professional', // Default role
      date: blog.published_at
        ? new Date(blog.published_at).toISOString()
        : new Date().toISOString(),
      readTime: this.calculateReadTime(blog.content),
      category: blog.category || 'General',
      category_name: blog.category || 'General', // alias for dashboard
      image: blog.featured_image || '',
      likes: options?.likeCount ?? 0,
      comments: options?.commentCount ?? 0,
      user_has_liked: options?.userHasLiked,
      slug: blog.slug,
      content: blog.content,
      author_id: blog.author_id,
      is_published: blog.is_published,
      status, // approved | draft for dashboard
      published_at: blog.published_at,
      tags: blog.tags,
      created_at: blog.created_at,
      updated_at: blog.updated_at,
    };
  }

  serializeMany(
    blogs: (Blog & { author?: User })[],
    authors?: Map<string, User>,
    countMap?: Map<string, { likeCount: number; commentCount: number }>,
  ): SerializedBlog[] {
    return blogs.map((blog) => {
      const author = authors
        ? authors.get(blog.author_id)
        : (blog as Blog & { author?: User }).author;
      const counts = countMap?.get(blog.id);
      return this.serialize(blog, author, {
        likeCount: counts?.likeCount,
        commentCount: counts?.commentCount,
      });
    });
  }
}
