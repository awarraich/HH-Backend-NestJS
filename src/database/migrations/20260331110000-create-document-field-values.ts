import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateDocumentFieldValues20260331110000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE document_field_values (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        template_id UUID NOT NULL REFERENCES competency_templates(id) ON DELETE CASCADE,
        field_id VARCHAR(255) NOT NULL,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        value JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (template_id, field_id, user_id)
      )
    `);

    await queryRunner.query(`CREATE INDEX idx_dfv_template ON document_field_values(template_id)`);
    await queryRunner.query(`CREATE INDEX idx_dfv_user ON document_field_values(user_id)`);
    await queryRunner.query(`CREATE INDEX idx_dfv_template_user ON document_field_values(template_id, user_id)`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS document_field_values`);
  }
}
