import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

/**
 * Adds the `interview_details` JSONB column (mirrors the existing `offer_details`) and
 * two composite indexes to keep the paginated organization applications list fast as
 * the table grows.
 */
export class AddInterviewDetailsAndIndexesToJobApplications20260416100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'job_applications',
      new TableColumn({
        name: 'interview_details',
        type: 'jsonb',
        isNullable: true,
      }),
    );

    await queryRunner.createIndex(
      'job_applications',
      new TableIndex({
        name: 'idx_job_apps_job_posting_status_created',
        columnNames: ['job_posting_id', 'status', 'created_at'],
      }),
    );

    await queryRunner.createIndex(
      'job_applications',
      new TableIndex({
        name: 'idx_job_apps_status_created',
        columnNames: ['status', 'created_at'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('job_applications', 'idx_job_apps_status_created');
    await queryRunner.dropIndex('job_applications', 'idx_job_apps_job_posting_status_created');
    await queryRunner.dropColumn('job_applications', 'interview_details');
  }
}
