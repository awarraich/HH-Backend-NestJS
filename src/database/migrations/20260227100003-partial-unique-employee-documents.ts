import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Replaces the full unique constraint on (employee_id, document_type_id) with a
 * partial unique index that applies only when deleted_at IS NULL. This allows
 * re-uploading a document of the same type after soft-deleting the previous one.
 */
export class PartialUniqueEmployeeDocuments20260227100003
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropUniqueConstraint(
      'employee_documents',
      'uq_employee_documents_employee_id_document_type_id',
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_employee_documents_employee_id_document_type_id
       ON employee_documents (employee_id, document_type_id)
       WHERE deleted_at IS NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS uq_employee_documents_employee_id_document_type_id`,
    );
    await queryRunner.query(
      `ALTER TABLE employee_documents
       ADD CONSTRAINT uq_employee_documents_employee_id_document_type_id
       UNIQUE (employee_id, document_type_id)`,
    );
  }
}
