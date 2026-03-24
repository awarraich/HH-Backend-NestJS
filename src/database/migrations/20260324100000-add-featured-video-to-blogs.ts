import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Optional main/hero video for a blog post (uploaded file URL or external e.g. YouTube).
 */
export class AddFeaturedVideoToBlogs20260324100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "blogs"
      ADD COLUMN IF NOT EXISTS "featured_video" varchar(2000) NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "blogs"
      DROP COLUMN IF EXISTS "featured_video"
    `);
  }
}
