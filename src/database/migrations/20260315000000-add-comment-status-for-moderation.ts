import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Add status to blog_comments: pending | approved | rejected.
 * Only approved comments are shown publicly; blogger or admin can approve or delete.
 */
export class AddCommentStatusForModeration20260315000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('blog_comments');
    if (table && !table.findColumnByName('status')) {
      await queryRunner.addColumn(
        'blog_comments',
        new TableColumn({
          name: 'status',
          type: 'varchar',
          length: '20',
          default: "'pending'",
          isNullable: false,
        }),
      );
      await queryRunner.query(`
        UPDATE blog_comments SET status = 'approved';
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('blog_comments');
    if (table?.findColumnByName('status')) {
      await queryRunner.dropColumn('blog_comments', 'status');
    }
  }
}
