import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableColumn,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

/**
 * Phase 2 of the document-workflow lifecycle hardening: submission +
 * approval flow on top of the Phase 1 status column.
 *
 * Three things happen here:
 *
 * 1. Extend `document_template_user_assignments` with reviewer / reject
 *    metadata so the same row tracks who submitted, who reviewed, and
 *    why something was rejected. Status is the existing column, just
 *    extended to 'submitted' | 'approved' | 'rejected' values.
 *
 * 2. Add `requires_review` on `competency_templates` — admin toggle
 *    deciding whether the auto-`completed` state is terminal (review
 *    not needed) or whether the employee must explicitly /submit and
 *    an admin must /approve.
 *
 * 3. Create `document_assignment_events` — append-only audit log of
 *    every lifecycle transition. Source of truth for "who did what
 *    when" questions that the denormalized columns can't answer once
 *    state is overwritten (e.g. "this was rejected once before being
 *    approved").
 */
export class AddSubmissionLifecycleToDocumentAssignments20260507130000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ─── 1. Lifecycle columns on document_template_user_assignments ───
    const assignmentColumns: TableColumn[] = [];
    if (!(await queryRunner.hasColumn('document_template_user_assignments', 'submitted_at'))) {
      assignmentColumns.push(new TableColumn({ name: 'submitted_at', type: 'timestamptz', isNullable: true }));
    }
    if (!(await queryRunner.hasColumn('document_template_user_assignments', 'submitted_by'))) {
      assignmentColumns.push(new TableColumn({ name: 'submitted_by', type: 'uuid', isNullable: true }));
    }
    if (!(await queryRunner.hasColumn('document_template_user_assignments', 'reviewed_at'))) {
      assignmentColumns.push(new TableColumn({ name: 'reviewed_at', type: 'timestamptz', isNullable: true }));
    }
    if (!(await queryRunner.hasColumn('document_template_user_assignments', 'reviewed_by'))) {
      assignmentColumns.push(new TableColumn({ name: 'reviewed_by', type: 'uuid', isNullable: true }));
    }
    if (!(await queryRunner.hasColumn('document_template_user_assignments', 'rejection_reason'))) {
      assignmentColumns.push(new TableColumn({ name: 'rejection_reason', type: 'text', isNullable: true }));
    }
    if (assignmentColumns.length > 0) {
      await queryRunner.addColumns('document_template_user_assignments', assignmentColumns);
    }

    // ─── 2. requires_review toggle on competency_templates ───
    if (!(await queryRunner.hasColumn('competency_templates', 'requires_review'))) {
      await queryRunner.addColumn(
        'competency_templates',
        new TableColumn({
          name: 'requires_review',
          type: 'boolean',
          default: false,
          isNullable: false,
        }),
      );
    }

    // ─── 3. Append-only audit log: document_assignment_events ───
    const tableExists = await queryRunner.hasTable('document_assignment_events');
    if (!tableExists) {
      await queryRunner.createTable(
        new Table({
          name: 'document_assignment_events',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'gen_random_uuid()',
            },
            { name: 'assignment_id', type: 'uuid', isNullable: false },
            // Free-form on purpose so future event types ('reopened',
            // 'reassigned', 'reminded') don't need a migration. Index
            // covers status-change queries; aliasing isn't worth it.
            { name: 'event', type: 'varchar', length: '32', isNullable: false },
            // Actor who triggered the transition. NULL for system-driven
            // events (auto-completion when last field is filled).
            { name: 'actor_user_id', type: 'uuid', isNullable: true },
            // Optional payload — { from_status, to_status, reason, etc. }
            // jsonb so each event type can carry its own shape without
            // schema churn.
            { name: 'payload', type: 'jsonb', isNullable: true },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'now()',
              isNullable: false,
            },
          ],
        }),
        true,
      );
      await queryRunner.createIndex(
        'document_assignment_events',
        new TableIndex({
          name: 'idx_dae_assignment_id',
          columnNames: ['assignment_id'],
        }),
      );
      await queryRunner.createIndex(
        'document_assignment_events',
        new TableIndex({
          name: 'idx_dae_actor_user_id',
          columnNames: ['actor_user_id'],
        }),
      );
      await queryRunner.createForeignKey(
        'document_assignment_events',
        new TableForeignKey({
          columnNames: ['assignment_id'],
          referencedTableName: 'document_template_user_assignments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.hasTable('document_assignment_events')) {
      await queryRunner.dropTable('document_assignment_events', true);
    }
    if (await queryRunner.hasColumn('competency_templates', 'requires_review')) {
      await queryRunner.dropColumn('competency_templates', 'requires_review');
    }
    for (const col of [
      'rejection_reason',
      'reviewed_by',
      'reviewed_at',
      'submitted_by',
      'submitted_at',
    ]) {
      if (await queryRunner.hasColumn('document_template_user_assignments', col)) {
        await queryRunner.dropColumn('document_template_user_assignments', col);
      }
    }
  }
}
