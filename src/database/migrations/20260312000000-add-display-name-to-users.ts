import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Add displayName to users for blog byline (e.g. "Dr. Jane Smith").
 * Falls back to firstName + lastName when null.
 */
export class AddDisplayNameToUsers20260312000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('users');
    if (table && !table.findColumnByName('displayName')) {
      await queryRunner.addColumn(
        'users',
        new TableColumn({
          name: 'displayName',
          type: 'varchar',
          length: '255',
          isNullable: true,
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('users', 'displayName');
  }
}
