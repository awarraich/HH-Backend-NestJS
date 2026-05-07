import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Per-instance role + field-value tables for the role-scoped competency
 * fill flow ("v2"). Adds a parallel storage path alongside the existing
 * `competency_assignments.field_values` JSONB blob; the old single-supervisor
 * flow keeps working untouched on the legacy columns.
 *
 * New tables:
 *   - competency_assignment_roles       — one row per (assignment, role, user)
 *   - competency_assignment_field_values — per-instance, per-field values
 *
 * Plus a nullable `employee_user_id` column on competency_assignments so the
 * HR-File-side panel can list workflows by employee without round-tripping
 * through the role-assignment join. Old rows leave it NULL and continue to
 * use the legacy supervisor-only model.
 */
export class CreateCompetencyAssignmentRoles20260507100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── employee_user_id on competency_assignments ─────────────────────
    const hasEmployeeCol = await queryRunner.hasColumn(
      'competency_assignments',
      'employee_user_id',
    );
    if (!hasEmployeeCol) {
      await queryRunner.query(`
        ALTER TABLE competency_assignments
        ADD COLUMN employee_user_id UUID NULL
        REFERENCES users(id) ON DELETE SET NULL
      `);
      await queryRunner.query(
        `CREATE INDEX idx_ca_employee_user ON competency_assignments(employee_user_id)`,
      );
    }

    // ── competency_assignment_roles ────────────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS competency_assignment_roles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        assignment_id UUID NOT NULL REFERENCES competency_assignments(id) ON DELETE CASCADE,
        role_id UUID NOT NULL REFERENCES document_workflow_roles(id) ON DELETE RESTRICT,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        recipient_type VARCHAR(32) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'in_progress', 'submitted')),
        submitted_at TIMESTAMPTZ,
        fill_token VARCHAR(128) UNIQUE,
        fill_token_expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (assignment_id, role_id, user_id)
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS idx_car_assignment ON competency_assignment_roles(assignment_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS idx_car_user ON competency_assignment_roles(user_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS idx_car_token ON competency_assignment_roles(fill_token)`,
    );

    // ── competency_assignment_field_values ─────────────────────────────
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS competency_assignment_field_values (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        assignment_id UUID NOT NULL REFERENCES competency_assignments(id) ON DELETE CASCADE,
        field_id VARCHAR(255) NOT NULL,
        value_text TEXT,
        value_json JSONB,
        filled_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        filled_by_role_id UUID REFERENCES document_workflow_roles(id) ON DELETE SET NULL,
        signature_audit JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (assignment_id, field_id)
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS idx_cafv_assignment ON competency_assignment_field_values(assignment_id)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DROP TABLE IF EXISTS competency_assignment_field_values`,
    );
    await queryRunner.query(
      `DROP TABLE IF EXISTS competency_assignment_roles`,
    );
    const hasEmployeeCol = await queryRunner.hasColumn(
      'competency_assignments',
      'employee_user_id',
    );
    if (hasEmployeeCol) {
      await queryRunner.query(
        `DROP INDEX IF EXISTS idx_ca_employee_user`,
      );
      await queryRunner.query(
        `ALTER TABLE competency_assignments DROP COLUMN employee_user_id`,
      );
    }
  }
}
