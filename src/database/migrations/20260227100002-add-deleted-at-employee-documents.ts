import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

export class AddDeletedAtEmployeeDocuments20260227100002 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'employee_documents',
      new TableColumn({
        name: 'deleted_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
    await queryRunner.createIndex(
      'employee_documents',
      new TableIndex({
        name: 'idx_employee_documents_deleted_at',
        columnNames: ['deleted_at'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('employee_documents', 'idx_employee_documents_deleted_at');
    await queryRunner.dropColumn('employee_documents', 'deleted_at');
  }
}
