import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddDocumentTemplateIdsToReferrals20260403000001 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE referrals
      ADD COLUMN IF NOT EXISTS document_template_ids uuid[] DEFAULT NULL
    `);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE referrals DROP COLUMN IF EXISTS document_template_ids
    `);
  }
}
