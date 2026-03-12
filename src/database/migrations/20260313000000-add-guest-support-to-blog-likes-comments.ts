import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Allow guests to like (by guest_id) and comment (by guest_name, guest_email).
 * - blog_likes: user_id nullable, add guest_id; unique per (blog_id, user_id) or (blog_id, guest_id).
 * - blog_comments: user_id nullable, add guest_name, guest_email.
 */
export class AddGuestSupportToBlogLikesComments20260313000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const likesTable = await queryRunner.getTable('blog_likes');
    if (likesTable) {
      const hasGuestId = likesTable.findColumnByName('guest_id');
      if (!hasGuestId) {
        await queryRunner.query(`DROP INDEX IF EXISTS "UQ_blog_likes_blog_user"`);
        await queryRunner.changeColumn(
          'blog_likes',
          'user_id',
          new TableColumn({
            name: 'user_id',
            type: 'uuid',
            isNullable: true,
          }),
        );
        await queryRunner.addColumn(
          'blog_likes',
          new TableColumn({
            name: 'guest_id',
            type: 'varchar',
            length: '64',
            isNullable: true,
          }),
        );
        await queryRunner.query(
          `CREATE UNIQUE INDEX "UQ_blog_likes_blog_user" ON "blog_likes" ("blog_id", "user_id") WHERE "user_id" IS NOT NULL`,
        );
        await queryRunner.query(
          `CREATE UNIQUE INDEX "UQ_blog_likes_blog_guest" ON "blog_likes" ("blog_id", "guest_id") WHERE "guest_id" IS NOT NULL`,
        );
      }
    }

    const commentsTable = await queryRunner.getTable('blog_comments');
    if (commentsTable) {
      if (!commentsTable.findColumnByName('guest_name')) {
        await queryRunner.changeColumn(
          'blog_comments',
          'user_id',
          new TableColumn({
            name: 'user_id',
            type: 'uuid',
            isNullable: true,
          }),
        );
        await queryRunner.addColumn(
          'blog_comments',
          new TableColumn({
            name: 'guest_name',
            type: 'varchar',
            length: '255',
            isNullable: true,
          }),
        );
        await queryRunner.addColumn(
          'blog_comments',
          new TableColumn({
            name: 'guest_email',
            type: 'varchar',
            length: '254',
            isNullable: true,
          }),
        );
      }
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const likesTable = await queryRunner.getTable('blog_likes');
    if (likesTable?.findColumnByName('guest_id')) {
      await queryRunner.query(`DROP INDEX IF EXISTS "UQ_blog_likes_blog_guest"`);
      await queryRunner.query(`DROP INDEX IF EXISTS "UQ_blog_likes_blog_user"`);
      await queryRunner.dropColumn('blog_likes', 'guest_id');
      await queryRunner.changeColumn(
        'blog_likes',
        'user_id',
        new TableColumn({ name: 'user_id', type: 'uuid', isNullable: false }),
      );
      await queryRunner.query(
        `CREATE UNIQUE INDEX "UQ_blog_likes_blog_user" ON "blog_likes" ("blog_id", "user_id")`,
      );
    }

    const commentsTable = await queryRunner.getTable('blog_comments');
    if (commentsTable?.findColumnByName('guest_name')) {
      await queryRunner.dropColumn('blog_comments', 'guest_name');
      await queryRunner.dropColumn('blog_comments', 'guest_email');
      await queryRunner.changeColumn(
        'blog_comments',
        'user_id',
        new TableColumn({ name: 'user_id', type: 'uuid', isNullable: false }),
      );
    }
  }
}
