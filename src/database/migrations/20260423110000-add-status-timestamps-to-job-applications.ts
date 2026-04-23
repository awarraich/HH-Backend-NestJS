import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddStatusTimestampsToJobApplications20260423110000 implements MigrationInterface {
  private readonly columns = [
    'interview_scheduled_at',
    'offer_sent_at',
    'offer_accepted_at',
    'offer_declined_at',
    'rejected_at',
    'hired_at',
  ];

  public async up(queryRunner: QueryRunner): Promise<void> {
    for (const name of this.columns) {
      await queryRunner.addColumn(
        'job_applications',
        new TableColumn({
          name,
          type: 'timestamp with time zone',
          isNullable: true,
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    for (const name of [...this.columns].reverse()) {
      await queryRunner.dropColumn('job_applications', name);
    }
  }
}
