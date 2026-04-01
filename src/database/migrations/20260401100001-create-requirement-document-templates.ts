import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateRequirementDocumentTemplates20260401100001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE requirement_document_templates (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        requirement_tag_id UUID NOT NULL REFERENCES requirement_tags(id) ON DELETE CASCADE,
        document_template_id UUID NOT NULL REFERENCES competency_templates(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (requirement_tag_id, document_template_id)
      )
    `);

    await queryRunner.query(`CREATE INDEX idx_rdt_tag ON requirement_document_templates(requirement_tag_id)`);
    await queryRunner.query(`CREATE INDEX idx_rdt_template ON requirement_document_templates(document_template_id)`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS requirement_document_templates`);
  }
}
