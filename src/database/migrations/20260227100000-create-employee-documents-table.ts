import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateEmployeeDocumentsTable20260227100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'employee_documents',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          { name: 'document_type_id', type: 'uuid', isNullable: false },
          { name: 'file_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'file_path', type: 'varchar', length: '500', isNullable: false },
          { name: 'file_size_bytes', type: 'bigint', isNullable: true },
          { name: 'mime_type', type: 'varchar', length: '100', isNullable: true },
          { name: 'uploaded_by', type: 'uuid', isNullable: true },
          { name: 'extracted_text', type: 'text', isNullable: true },
          {
            name: 'extraction_status',
            type: 'varchar',
            length: '20',
            default: "'pending'",
            isNullable: false,
          },
          { name: 'extraction_error', type: 'text', isNullable: true },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'employee_documents',
      new TableUnique({
        name: 'uq_employee_documents_employee_id_document_type_id',
        columnNames: ['employee_id', 'document_type_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'employee_documents',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_documents_organization_id',
      }),
    );

    await queryRunner.createForeignKey(
      'employee_documents',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_documents_employee_id',
      }),
    );

    await queryRunner.createForeignKey(
      'employee_documents',
      new TableForeignKey({
        columnNames: ['document_type_id'],
        referencedTableName: 'hr_document_types',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
        name: 'fk_employee_documents_document_type_id',
      }),
    );

    await queryRunner.createForeignKey(
      'employee_documents',
      new TableForeignKey({
        columnNames: ['uploaded_by'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employee_documents_uploaded_by',
      }),
    );

    await queryRunner.createIndex(
      'employee_documents',
      new TableIndex({
        name: 'idx_employee_documents_organization_id',
        columnNames: ['organization_id'],
      }),
    );
    await queryRunner.createIndex(
      'employee_documents',
      new TableIndex({
        name: 'idx_employee_documents_employee_id',
        columnNames: ['employee_id'],
      }),
    );
    await queryRunner.createIndex(
      'employee_documents',
      new TableIndex({
        name: 'idx_employee_documents_document_type_id',
        columnNames: ['document_type_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('employee_documents', 'idx_employee_documents_document_type_id');
    await queryRunner.dropIndex('employee_documents', 'idx_employee_documents_employee_id');
    await queryRunner.dropIndex('employee_documents', 'idx_employee_documents_organization_id');
    await queryRunner.dropForeignKey('employee_documents', 'fk_employee_documents_uploaded_by');
    await queryRunner.dropForeignKey(
      'employee_documents',
      'fk_employee_documents_document_type_id',
    );
    await queryRunner.dropForeignKey('employee_documents', 'fk_employee_documents_employee_id');
    await queryRunner.dropForeignKey('employee_documents', 'fk_employee_documents_organization_id');
    await queryRunner.dropTable('employee_documents', true);
  }
}
