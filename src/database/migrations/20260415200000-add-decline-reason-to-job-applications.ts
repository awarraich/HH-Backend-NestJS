import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddDeclineReasonToJobApplications20260415200000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'job_applications',
      new TableColumn({
        name: 'decline_reason',
        type: 'text',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('job_applications', 'decline_reason');
  }
}
