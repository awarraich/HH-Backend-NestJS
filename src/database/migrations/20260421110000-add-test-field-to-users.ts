import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddTestFieldToUsers20260421110000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('users');
    if (table && !table.findColumnByName('test')) {
      await queryRunner.addColumn(
        'users',
        new TableColumn({
          name: 'test',
          type: 'varchar',
          length: '255',
          isNullable: true,
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('users', 'test');
  }
}
