import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableIndex,
  TableUnique,
} from 'typeorm';

/**
 * Add a `scheduled_date` column to `employee_shifts` so that each assignment
 * targets a specific calendar date. This is essential for recurring shifts
 * (FULL_WEEK, WEEKDAYS, etc.) where a single shift template covers multiple
 * days — the employee may only be available on some of those days.
 *
 * Changes:
 *  1. Add `scheduled_date DATE NOT NULL` (backfilled from shift.start_at).
 *  2. Drop the old unique constraint `(shift_id, employee_id)`.
 *  3. Add new unique constraint `(shift_id, employee_id, scheduled_date)`.
 *  4. Add index on `scheduled_date` for date-range queries.
 */
export class AddScheduledDateToEmployeeShifts20260414100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Add column as nullable first so we can backfill
    await queryRunner.addColumn(
      'employee_shifts',
      new TableColumn({
        name: 'scheduled_date',
        type: 'date',
        isNullable: true,
      }),
    );

    // 2. Backfill: derive scheduled_date from the parent shift's start_at
    await queryRunner.query(`
      UPDATE employee_shifts es
      SET scheduled_date = DATE(s.start_at)
      FROM shifts s
      WHERE es.shift_id = s.id
        AND es.scheduled_date IS NULL
    `);

    // 3. For any rows that still have NULL (orphaned FK etc.), use created_at
    await queryRunner.query(`
      UPDATE employee_shifts
      SET scheduled_date = DATE(created_at)
      WHERE scheduled_date IS NULL
    `);

    // 4. Now make it NOT NULL
    await queryRunner.changeColumn(
      'employee_shifts',
      'scheduled_date',
      new TableColumn({
        name: 'scheduled_date',
        type: 'date',
        isNullable: false,
      }),
    );

    // 5. Drop old unique constraint on (shift_id, employee_id).
    //    Look it up by columns rather than name — production may have it under
    //    an auto-generated name (e.g. UQ_<hash>) instead of the expected
    //    `uq_employee_shifts_shift_employee`.
    const oldUnique: { conname: string }[] = await queryRunner.query(`
      SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class t ON t.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = 'public'
        AND t.relname = 'employee_shifts'
        AND c.contype = 'u'
        AND (
          SELECT array_agg(a.attname ORDER BY a.attname)
          FROM unnest(c.conkey) AS k(attnum)
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
        ) = ARRAY['employee_id', 'shift_id']
    `);
    for (const { conname } of oldUnique) {
      await queryRunner.query(
        `ALTER TABLE "employee_shifts" DROP CONSTRAINT "${conname}"`,
      );
    }

    // 6. Add new unique constraint including scheduled_date
    await queryRunner.createUniqueConstraint(
      'employee_shifts',
      new TableUnique({
        name: 'uq_employee_shifts_shift_employee_date',
        columnNames: ['shift_id', 'employee_id', 'scheduled_date'],
      }),
    );

    // 7. Add index on scheduled_date for date-range queries
    await queryRunner.createIndex(
      'employee_shifts',
      new TableIndex({
        name: 'idx_employee_shifts_scheduled_date',
        columnNames: ['scheduled_date'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Reverse: drop index, drop new constraint, add old constraint, drop column
    await queryRunner.dropIndex(
      'employee_shifts',
      'idx_employee_shifts_scheduled_date',
    );

    await queryRunner.dropUniqueConstraint(
      'employee_shifts',
      'uq_employee_shifts_shift_employee_date',
    );

    // Before re-adding the old constraint, deduplicate rows that share the
    // same (shift_id, employee_id) but differ on scheduled_date — keep the
    // earliest one (smallest id).
    await queryRunner.query(`
      DELETE FROM employee_shifts
      WHERE id NOT IN (
        SELECT MIN(id)
        FROM employee_shifts
        GROUP BY shift_id, employee_id
      )
    `);

    await queryRunner.createUniqueConstraint(
      'employee_shifts',
      new TableUnique({
        name: 'uq_employee_shifts_shift_employee',
        columnNames: ['shift_id', 'employee_id'],
      }),
    );

    await queryRunner.dropColumn('employee_shifts', 'scheduled_date');
  }
}
