import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

/**
 * Adds a per-assignment status column to `scheduled_task_assignments` so the
 * employee portal can accept/decline a clinic appointment / field visit /
 * transport trip / pharmacy prescription independently of the task's overall
 * lifecycle status. Mirrors `employee_shifts.status` semantics: PENDING by
 * default, transitioned to CONFIRMED / DECLINED by the assignee.
 *
 * Existing rows backfill to PENDING — they were created without an explicit
 * employee response and the org-portal can re-assign or transition the task
 * itself if the employee never responds.
 */
export class AddStatusToScheduledTaskAssignments20260507110000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const exists = await queryRunner.hasColumn('scheduled_task_assignments', 'status');
    if (!exists) {
      await queryRunner.addColumn(
        'scheduled_task_assignments',
        new TableColumn({
          name: 'status',
          type: 'varchar',
          length: '32',
          default: "'PENDING'",
          isNullable: false,
        }),
      );
    }

    await queryRunner.createIndex(
      'scheduled_task_assignments',
      new TableIndex({
        name: 'idx_scheduled_task_assignments_status',
        columnNames: ['status'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner
      .dropIndex('scheduled_task_assignments', 'idx_scheduled_task_assignments_status')
      .catch(() => {});
    const exists = await queryRunner.hasColumn('scheduled_task_assignments', 'status');
    if (exists) {
      await queryRunner.dropColumn('scheduled_task_assignments', 'status');
    }
  }
}
