import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class EmployeeDocumentTypesNoOrg20260305100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.changeColumn(
      'hr_document_types',
      'organization_id',
      new TableColumn({
        name: 'organization_id',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS uq_hr_document_types_org_employee_code`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_hr_document_types_employee_code
       ON hr_document_types (employee_id, code)
       WHERE employee_id IS NOT NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS uq_hr_document_types_employee_code`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_hr_document_types_org_employee_code
       ON hr_document_types (organization_id, employee_id, code)
       WHERE employee_id IS NOT NULL`,
    );
    await queryRunner.changeColumn(
      'hr_document_types',
      'organization_id',
      new TableColumn({
        name: 'organization_id',
        type: 'uuid',
        isNullable: false,
      }),
    );
  }
}
