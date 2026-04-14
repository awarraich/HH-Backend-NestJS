import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateDocumentTemplateUserAssignments20260401100002 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE document_template_user_assignments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        template_id UUID NOT NULL REFERENCES competency_templates(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role_id UUID NOT NULL REFERENCES document_workflow_roles(id) ON DELETE CASCADE,
        assigned_by UUID REFERENCES users(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (template_id, user_id, role_id)
      )
    `);

    await queryRunner.query(`CREATE INDEX idx_dtua_template ON document_template_user_assignments(template_id)`);
    await queryRunner.query(`CREATE INDEX idx_dtua_user ON document_template_user_assignments(user_id)`);
    await queryRunner.query(`CREATE INDEX idx_dtua_template_user ON document_template_user_assignments(template_id, user_id)`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS document_template_user_assignments`);
  }
}
