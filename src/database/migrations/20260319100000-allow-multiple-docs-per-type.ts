import { MigrationInterface, QueryRunner } from 'typeorm';

export class AllowMultipleDocsPerType20260319100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP INDEX IF EXISTS uq_employee_documents_employee_id_document_type_id`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE UNIQUE INDEX uq_employee_documents_employee_id_document_type_id
       ON employee_documents (employee_id, document_type_id)
       WHERE deleted_at IS NULL`,
    );
  }
}
