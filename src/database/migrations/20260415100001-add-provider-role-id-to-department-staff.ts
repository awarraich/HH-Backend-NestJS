import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableForeignKey,
  TableIndex,
} from 'typeorm';

/**
 * Adds `provider_role_id` (UUID FK → provider_roles.id) to `department_staff`
 * so a department's staff row is linked to a real provider role by UUID
 * rather than the free-text `staff_type` code. Backfills existing rows by
 * matching `staff_type` (case-insensitive) against `provider_roles.code`.
 * The legacy `staff_type` column is retained for backward compatibility.
 */
export class AddProviderRoleIdToDepartmentStaff20260415100001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'department_staff',
      new TableColumn({
        name: 'provider_role_id',
        type: 'uuid',
        isNullable: true,
      }),
    );

    await queryRunner.createIndex(
      'department_staff',
      new TableIndex({
        name: 'idx_department_staff_provider_role_id',
        columnNames: ['provider_role_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'department_staff',
      new TableForeignKey({
        name: 'fk_department_staff_provider_role',
        columnNames: ['provider_role_id'],
        referencedTableName: 'provider_roles',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
      }),
    );

    await queryRunner.query(`
      UPDATE department_staff ds
      SET provider_role_id = pr.id
      FROM provider_roles pr
      WHERE ds.provider_role_id IS NULL
        AND LOWER(ds.staff_type) = LOWER(pr.code)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropForeignKey(
      'department_staff',
      'fk_department_staff_provider_role',
    );
    await queryRunner.dropIndex(
      'department_staff',
      'idx_department_staff_provider_role_id',
    );
    await queryRunner.dropColumn('department_staff', 'provider_role_id');
  }
}
