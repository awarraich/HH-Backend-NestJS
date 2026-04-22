import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Adds a per-job snapshot of the application form field definitions to
 * `job_postings`. Before this migration, each posting referenced the
 * organization-level setup by ID arrays (`details.required_fields` /
 * `details.optional_fields`), so later edits to the org setup retroactively
 * mutated every past posting's form. The snapshot is the new source of
 * truth: seeded at create time from the org setup and evolved independently
 * per posting. Old rows stay on the legacy ID-reference path until re-saved.
 */
export class AddApplicationFieldsSnapshotToJobPostings20260421000000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('job_postings');
    if (!table) return;

    const exists = table.columns.some(
      (c) => c.name === 'application_fields_snapshot',
    );
    if (exists) return;

    await queryRunner.addColumn(
      'job_postings',
      new TableColumn({
        name: 'application_fields_snapshot',
        type: 'jsonb',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('job_postings');
    if (!table) return;
    const exists = table.columns.some(
      (c) => c.name === 'application_fields_snapshot',
    );
    if (exists) {
      await queryRunner.dropColumn('job_postings', 'application_fields_snapshot');
    }
  }
}
