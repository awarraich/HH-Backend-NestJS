import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

/**
 * Adds `applicant_user_id` (nullable uuid) to `job_applications` so the Send
 * Offer → Role Assignment flow can find the applicant's user record without
 * relying on `applicant_email` matching `users.email` (which breaks when the
 * candidate types a different email on the apply form than their account
 * email, or when the application was submitted as a guest and the user signed
 * up later).
 *
 * Also backfills the new column from existing email matches so rows created
 * before this migration get linked where a matching user exists. No FK —
 * applications can outlive user deletion, and the relation is read-only
 * (the column is never set via cascades).
 */
export class AddApplicantUserIdToJobApplications20260417100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'job_applications',
      new TableColumn({
        name: 'applicant_user_id',
        type: 'uuid',
        isNullable: true,
      }),
    );

    await queryRunner.createIndex(
      'job_applications',
      new TableIndex({
        name: 'IDX_job_applications_applicant_user_id',
        columnNames: ['applicant_user_id'],
      }),
    );

    // Backfill: link each row to the user whose email matches applicant_email
    // (case-insensitive). Rows without a matching user stay null.
    await queryRunner.query(`
      UPDATE job_applications ja
      SET applicant_user_id = u.id
      FROM users u
      WHERE ja.applicant_user_id IS NULL
        AND ja.applicant_email IS NOT NULL
        AND LOWER(u.email) = LOWER(ja.applicant_email)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'job_applications',
      'IDX_job_applications_applicant_user_id',
    );
    await queryRunner.dropColumn('job_applications', 'applicant_user_id');
  }
}
