import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Adds missing FK constraints from user-reference columns across several
 * tables so that deleting a user row either cascades the owned data or
 * nulls the audit pointer, instead of leaving dangling UUIDs behind.
 *
 * Motivation: the admin-panel User delete path only relied on TypeORM
 * relation cascades. Columns that were declared as plain `uuid` with no
 * `@ManyToOne(() => User)` decorator had no DB-level FK — those pointers
 * quietly outlived the user row. This migration fixes that class of bug
 * at the schema layer so any future delete path is automatically correct.
 *
 * Columns handled:
 *   - job_applications.applicant_user_id              → SET NULL  (keep application history)
 *   - offer_letter_assignment_roles.user_id           → CASCADE   (role fill targeted at this user only)
 *   - offer_letter_assignments.created_by             → SET NULL  (audit)
 *   - offer_letter_field_values.filled_by_user_id     → SET NULL  (audit)
 *   - organization_staff.created_by                   → SET NULL  (audit)
 *   - organization_staff.updated_by                   → SET NULL  (audit)
 *   - competency_assignments.supervisor_id            → CASCADE   (NOT NULL; row can't survive without a supervisor)
 *   - competency_assignments.created_by               → change from NO ACTION to SET NULL  (audit)
 *   - competency_templates.created_by                 → change from NO ACTION to SET NULL  (audit)
 *
 * Before adding each FK, dangling rows are cleaned up — SET NULL columns
 * get nulled, CASCADE columns get their row deleted — otherwise adding
 * the constraint would fail on historical bad data.
 */
export class AddUserFksForOrphanSafety20260418100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── 1. Clean up dangling references so the new FKs can be added ───────
    // SET NULL targets: just null the stale pointer.
    await queryRunner.query(`
      UPDATE job_applications
      SET applicant_user_id = NULL
      WHERE applicant_user_id IS NOT NULL
        AND applicant_user_id NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      UPDATE offer_letter_assignments
      SET created_by = NULL
      WHERE created_by IS NOT NULL
        AND created_by NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      UPDATE offer_letter_field_values
      SET filled_by_user_id = NULL
      WHERE filled_by_user_id IS NOT NULL
        AND filled_by_user_id NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      UPDATE organization_staff
      SET created_by = NULL
      WHERE created_by IS NOT NULL
        AND created_by NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      UPDATE organization_staff
      SET updated_by = NULL
      WHERE updated_by IS NOT NULL
        AND updated_by NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      UPDATE competency_assignments
      SET created_by = NULL
      WHERE created_by IS NOT NULL
        AND created_by NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      UPDATE competency_templates
      SET created_by = NULL
      WHERE created_by IS NOT NULL
        AND created_by NOT IN (SELECT id FROM users)
    `);

    // CASCADE targets: delete the whole row when the pointer is stale.
    await queryRunner.query(`
      DELETE FROM offer_letter_assignment_roles
      WHERE user_id NOT IN (SELECT id FROM users)
    `);
    await queryRunner.query(`
      DELETE FROM competency_assignments
      WHERE supervisor_id NOT IN (SELECT id FROM users)
    `);

    // ── 2. Drop pre-existing FKs that have the wrong (or no) ON DELETE ────
    // competency_* tables were created with `REFERENCES users(id)` and no
    // ON DELETE rule — Postgres generated constraint names we need to
    // discover and drop before we can recreate with explicit behaviour.
    await queryRunner.query(`
      DO $$
      DECLARE
        cons record;
      BEGIN
        FOR cons IN
          SELECT conname, conrelid::regclass::text AS tbl
          FROM pg_constraint
          WHERE contype = 'f'
            AND confrelid = 'users'::regclass
            AND conrelid::regclass::text IN (
              'competency_assignments',
              'competency_templates'
            )
        LOOP
          EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', cons.tbl, cons.conname);
        END LOOP;
      END $$;
    `);

    // ── 3. Add the new FKs with explicit ON DELETE behaviour ──────────────
    await queryRunner.query(`
      ALTER TABLE job_applications
      ADD CONSTRAINT FK_job_applications_applicant_user
      FOREIGN KEY (applicant_user_id)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
    await queryRunner.query(`
      ALTER TABLE offer_letter_assignment_roles
      ADD CONSTRAINT FK_offer_letter_assignment_roles_user
      FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE CASCADE
    `);
    await queryRunner.query(`
      ALTER TABLE offer_letter_assignments
      ADD CONSTRAINT FK_offer_letter_assignments_created_by
      FOREIGN KEY (created_by)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
    await queryRunner.query(`
      ALTER TABLE offer_letter_field_values
      ADD CONSTRAINT FK_offer_letter_field_values_filled_by_user
      FOREIGN KEY (filled_by_user_id)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
    await queryRunner.query(`
      ALTER TABLE organization_staff
      ADD CONSTRAINT FK_organization_staff_created_by
      FOREIGN KEY (created_by)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
    await queryRunner.query(`
      ALTER TABLE organization_staff
      ADD CONSTRAINT FK_organization_staff_updated_by
      FOREIGN KEY (updated_by)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
    await queryRunner.query(`
      ALTER TABLE competency_assignments
      ADD CONSTRAINT FK_competency_assignments_supervisor
      FOREIGN KEY (supervisor_id)
      REFERENCES users(id)
      ON DELETE CASCADE
    `);
    await queryRunner.query(`
      ALTER TABLE competency_assignments
      ADD CONSTRAINT FK_competency_assignments_created_by
      FOREIGN KEY (created_by)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
    await queryRunner.query(`
      ALTER TABLE competency_templates
      ADD CONSTRAINT FK_competency_templates_created_by
      FOREIGN KEY (created_by)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop the FKs we created. Back to the pre-migration state (plain UUIDs
    // with no referential integrity — which is what was there before).
    const drops: Array<[string, string]> = [
      ['job_applications', 'FK_job_applications_applicant_user'],
      ['offer_letter_assignment_roles', 'FK_offer_letter_assignment_roles_user'],
      ['offer_letter_assignments', 'FK_offer_letter_assignments_created_by'],
      ['offer_letter_field_values', 'FK_offer_letter_field_values_filled_by_user'],
      ['organization_staff', 'FK_organization_staff_created_by'],
      ['organization_staff', 'FK_organization_staff_updated_by'],
      ['competency_assignments', 'FK_competency_assignments_supervisor'],
      ['competency_assignments', 'FK_competency_assignments_created_by'],
      ['competency_templates', 'FK_competency_templates_created_by'],
    ];
    for (const [table, name] of drops) {
      await queryRunner.query(
        `ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS "${name}"`,
      );
    }
  }
}
