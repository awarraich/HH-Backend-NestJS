import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddTimezoneToOrganizations20260505100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const exists = await queryRunner.hasColumn('organizations', 'timezone');
    if (exists) return;
    await queryRunner.addColumn(
      'organizations',
      new TableColumn({
        name: 'timezone',
        type: 'varchar',
        length: '100',
        default: "'America/Los_Angeles'",
        isNullable: false,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const exists = await queryRunner.hasColumn('organizations', 'timezone');
    if (!exists) return;
    await queryRunner.dropColumn('organizations', 'timezone');
  }
}
