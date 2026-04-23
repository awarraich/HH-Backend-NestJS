import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableIndex,
} from 'typeorm';

/**
 * Promote `role` from inside the `notes` JSON blob to a first-class column on
 * `employee_shifts`. The MCP `assign_employee_to_shift` tool was stuffing the
 * role into notes (e.g. `{"role":"LN","rooms":[]}`), which makes role-based
 * queries require JSON parsing on every row and leaves the column unindexed.
 *
 * The notes column keeps its role copy too — the existing frontend grid is
 * keyed on `notes.role` and changing the read path is a separate FE ticket.
 */
export class AddRoleToEmployeeShifts20260421200000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'employee_shifts',
      new TableColumn({
        name: 'role',
        type: 'varchar',
        length: '50',
        isNullable: true,
      }),
    );

    // Backfill role from notes JSON where notes is valid JSON containing a
    // `role` key. Rows where notes is null, plain text, or malformed JSON
    // simply stay null — that's correct, we have nothing to promote.
    await queryRunner.query(`
      UPDATE employee_shifts
      SET role = (notes::jsonb)->>'role'
      WHERE notes IS NOT NULL
        AND notes ~ '^\\s*\\{'
        AND (notes::jsonb)->>'role' IS NOT NULL
    `);

    await queryRunner.createIndex(
      'employee_shifts',
      new TableIndex({
        name: 'idx_employee_shifts_shift_date_role',
        columnNames: ['shift_id', 'scheduled_date', 'role'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'employee_shifts',
      'idx_employee_shifts_shift_date_role',
    );
    await queryRunner.dropColumn('employee_shifts', 'role');
  }
}
