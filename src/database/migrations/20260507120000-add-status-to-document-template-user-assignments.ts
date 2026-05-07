import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

/**
 * Phase 1 of the document-workflow lifecycle hardening (see project doc):
 * denormalize the per-assignment status onto `document_template_user_assignments`
 * so the HR File dashboards stop recomputing "filled vs required" on every
 * render, and the employee's "needs action" list becomes a directly-indexable
 * `WHERE status = 'pending'` query.
 *
 * Status values match the lifecycle the service writes:
 *   pending     — no values saved yet
 *   in_progress — at least one but not all required fields saved
 *   completed   — every field assigned to this role has a saved value
 *   submitted / approved / rejected — reserved for Phase 2 (review flow)
 *
 * Backfill walks every existing assignment, unpacks the template's
 * `document_fields` JSONB to get the required field set for that role, and
 * compares against the count of saved `document_field_values` rows. Done in
 * pure SQL so the migration is idempotent and fast at any volume.
 */
export class AddStatusToDocumentTemplateUserAssignments20260507120000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const hasStatus = await queryRunner.hasColumn(
      'document_template_user_assignments',
      'status',
    );
    if (!hasStatus) {
      await queryRunner.addColumn(
        'document_template_user_assignments',
        new TableColumn({
          name: 'status',
          type: 'varchar',
          length: '32',
          default: "'pending'",
          isNullable: false,
        }),
      );
    }
    const hasStartedAt = await queryRunner.hasColumn(
      'document_template_user_assignments',
      'started_at',
    );
    if (!hasStartedAt) {
      await queryRunner.addColumn(
        'document_template_user_assignments',
        new TableColumn({
          name: 'started_at',
          type: 'timestamptz',
          isNullable: true,
        }),
      );
    }
    const hasCompletedAt = await queryRunner.hasColumn(
      'document_template_user_assignments',
      'completed_at',
    );
    if (!hasCompletedAt) {
      await queryRunner.addColumn(
        'document_template_user_assignments',
        new TableColumn({
          name: 'completed_at',
          type: 'timestamptz',
          isNullable: true,
        }),
      );
    }

    // Composite index for the dominant employee-side query path:
    // "show this user's assignments filtered by status" (the Documents
    // / Needs Action / Completed tabs). Single-column status alone has
    // too few distinct values to be useful; pairing it with user_id
    // covers the actual filter the employee portal makes.
    await queryRunner.createIndex(
      'document_template_user_assignments',
      new TableIndex({
        name: 'idx_dtua_user_status',
        columnNames: ['user_id', 'status'],
      }),
    );

    // Backfill. CTEs first compute (expected_count, actual_count,
    // earliest write, latest write) per assignment by joining the
    // assignment's template's document_fields JSONB to the saved
    // document_field_values rows for that user. The UPDATE then maps
    // those counts to the lifecycle status.
    //
    // Notes:
    //   - jsonb_array_elements unpacks document_fields into one row per
    //     field. The `field->>'assignedRoleId' = role_id::text` predicate
    //     scopes to the fields THIS assignment's role is responsible for.
    //   - Assignments whose template has no fields for the user's role
    //     (degenerate config) drop out of the CTE and stay at the default
    //     'pending' — accurate, since no work is required of them.
    //   - LEFT JOIN on actual_per_assignment so assignments with zero
    //     saved values (`actual_count IS NULL`) still flow through and
    //     map to 'pending'.
    await queryRunner.query(`
      WITH expected_per_assignment AS (
        SELECT
          dtua.id AS assignment_id,
          COUNT(*) AS expected_count
        FROM document_template_user_assignments dtua
        JOIN competency_templates ct ON ct.id = dtua.template_id
        CROSS JOIN LATERAL jsonb_array_elements(ct.document_fields) AS field
        WHERE field->>'assignedRoleId' = dtua.role_id::text
        GROUP BY dtua.id
      ),
      actual_per_assignment AS (
        SELECT
          dtua.id AS assignment_id,
          COUNT(*) AS actual_count,
          MIN(dfv.created_at) AS started_at,
          MAX(dfv.updated_at) AS last_updated_at
        FROM document_template_user_assignments dtua
        JOIN competency_templates ct ON ct.id = dtua.template_id
        CROSS JOIN LATERAL jsonb_array_elements(ct.document_fields) AS field
        JOIN document_field_values dfv
          ON dfv.template_id = dtua.template_id
         AND dfv.user_id = dtua.user_id
         AND dfv.field_id = field->>'id'
        WHERE field->>'assignedRoleId' = dtua.role_id::text
        GROUP BY dtua.id
      )
      UPDATE document_template_user_assignments dtua
      SET
        status = CASE
          WHEN apa.actual_count IS NULL OR apa.actual_count = 0 THEN 'pending'
          WHEN apa.actual_count >= epa.expected_count THEN 'completed'
          ELSE 'in_progress'
        END,
        started_at = apa.started_at,
        completed_at = CASE
          WHEN apa.actual_count IS NOT NULL AND apa.actual_count >= epa.expected_count
          THEN apa.last_updated_at
          ELSE NULL
        END
      FROM expected_per_assignment epa
      LEFT JOIN actual_per_assignment apa ON apa.assignment_id = epa.assignment_id
      WHERE dtua.id = epa.assignment_id;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner
      .dropIndex('document_template_user_assignments', 'idx_dtua_user_status')
      .catch(() => {});
    for (const col of ['completed_at', 'started_at', 'status']) {
      const exists = await queryRunner.hasColumn(
        'document_template_user_assignments',
        col,
      );
      if (exists) {
        await queryRunner.dropColumn('document_template_user_assignments', col);
      }
    }
  }
}
