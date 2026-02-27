import { Blog } from '../entities/blog.entity';
import { User } from '../../../authentication/entities/user.entity';

export class BlogSerializer {
  // Calculate read time based on content (avg 200 words per minute)
  private calculateReadTime(content: string): string {
    if (!content) return '1 min read';
    const words = content.trim().split(/\s+/).length;
    const minutes = Math.ceil(words / 200);
    return `${minutes} min read`;
  }

  serialize(blog: Blog, author?: User): any {
    // Dashboard expects status: approved | pending | rejected | draft; backend has is_published only
    const status = blog.is_published ? 'approved' : 'draft';
    return {
      id: blog.id,
      title: blog.title,
      excerpt: blog.excerpt,
      short_description: blog.excerpt ?? '', // alias for blogger dashboard
      author: author ? `${author.firstName} ${author.lastName}` : 'Unknown Author',
      authorRole: 'Healthcare Professional', // Default role
      date: blog.published_at ? new Date(blog.published_at).toISOString() : new Date().toISOString(),
      readTime: this.calculateReadTime(blog.content),
      category: blog.category || 'General',
      category_name: blog.category || 'General', // alias for dashboard
      image: blog.featured_image || '',
      likes: 0, // Default - can be extended with a likes system
      comments: 0, // Default - can be extended with a comments system
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

  serializeMany(blogs: Blog[], authors?: Map<string, User>): any[] {
    return blogs.map((blog) => {
      const author = authors ? authors.get(blog.author_id) : undefined;
      return this.serialize(blog, author);
    });
  }
}
