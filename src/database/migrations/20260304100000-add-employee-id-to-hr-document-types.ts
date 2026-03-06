import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableForeignKey,
  TableIndex,
  TableUnique,
} from 'typeorm';

export class AddEmployeeIdToHrDocumentTypes20260304100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropUniqueConstraint(
      'hr_document_types',
      'uq_hr_document_types_organization_id_code',
    );
    await queryRunner.addColumn(
      'hr_document_types',
      new TableColumn({
        name: 'employee_id',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.createForeignKey(
      'hr_document_types',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_hr_document_types_employee_id',
      }),
    );
    await queryRunner.createIndex(
      'hr_document_types',
      new TableIndex({
        name: 'idx_hr_document_types_employee_id',
        columnNames: ['employee_id'],
      }),
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_hr_document_types_org_code_org_only
       ON hr_document_types (organization_id, code)
       WHERE employee_id IS NULL`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_hr_document_types_org_employee_code
       ON hr_document_types (organization_id, employee_id, code)
       WHERE employee_id IS NOT NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS uq_hr_document_types_org_employee_code`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS uq_hr_document_types_org_code_org_only`,
    );
    await queryRunner.dropIndex(
      'hr_document_types',
      'idx_hr_document_types_employee_id',
    );
    await queryRunner.dropForeignKey(
      'hr_document_types',
      'fk_hr_document_types_employee_id',
    );
    await queryRunner.dropColumn('hr_document_types', 'employee_id');
    await queryRunner.createUniqueConstraint(
      'hr_document_types',
      new TableUnique({
        name: 'uq_hr_document_types_organization_id_code',
        columnNames: ['organization_id', 'code'],
      }),
    );
  }
}
