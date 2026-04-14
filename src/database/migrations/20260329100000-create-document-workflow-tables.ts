import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateDocumentWorkflowTables20260329100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE competency_templates (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        mode VARCHAR(20) NOT NULL CHECK (mode IN ('grid', 'document')),
        layout JSONB NOT NULL DEFAULT '{"rows":1,"cols":1,"cells":[[]]}',
        document_fields JSONB NOT NULL DEFAULT '[]',
        roles JSONB NOT NULL DEFAULT '[]',
        pdf_file_key VARCHAR(500),
        pdf_original_name VARCHAR(255),
        pdf_size_bytes INTEGER,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    await queryRunner.query(`CREATE INDEX idx_ct_org ON competency_templates(organization_id)`);
    await queryRunner.query(`CREATE INDEX idx_ct_mode ON competency_templates(organization_id, mode)`);

    await queryRunner.query(`
      CREATE TABLE competency_assignments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        template_id UUID NOT NULL REFERENCES competency_templates(id) ON DELETE RESTRICT,
        template_snapshot JSONB NOT NULL,
        name VARCHAR(255) NOT NULL,
        job_title VARCHAR(255) NOT NULL,
        supervisor_id UUID NOT NULL REFERENCES users(id),
        status VARCHAR(20) NOT NULL DEFAULT 'sent'
          CHECK (status IN ('draft', 'sent', 'in_progress', 'completed', 'voided')),
        field_values JSONB NOT NULL DEFAULT '{}',
        employee_id UUID REFERENCES users(id),
        employee_signature TEXT,
        employee_signed_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    await queryRunner.query(`CREATE INDEX idx_ca_org ON competency_assignments(organization_id)`);
    await queryRunner.query(`CREATE INDEX idx_ca_status ON competency_assignments(organization_id, status)`);
    await queryRunner.query(`CREATE INDEX idx_ca_supervisor ON competency_assignments(supervisor_id)`);
    await queryRunner.query(`CREATE INDEX idx_ca_employee ON competency_assignments(employee_id)`);
    await queryRunner.query(`CREATE INDEX idx_ca_template ON competency_assignments(template_id)`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS competency_assignments`);
    await queryRunner.query(`DROP TABLE IF EXISTS competency_templates`);
  }
}
  