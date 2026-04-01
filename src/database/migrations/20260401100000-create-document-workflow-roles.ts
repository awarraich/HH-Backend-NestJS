import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateDocumentWorkflowRoles20260401100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE document_workflow_roles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        is_default BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (organization_id, name)
      )
    `);

    await queryRunner.query(`CREATE INDEX idx_dwr_org ON document_workflow_roles(organization_id)`);

    // Seed default roles (no organization, available to all)
    await queryRunner.query(`
      INSERT INTO document_workflow_roles (name, description, is_default)
      VALUES
        ('Supervisor', 'Default supervisor role for document workflows', true),
        ('Employee', 'Default employee role for document workflows', true)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS document_workflow_roles`);
  }
}
