import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddOfferDetailsToJobApplications20260414100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'job_applications',
      new TableColumn({
        name: 'offer_details',
        type: 'jsonb',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('job_applications', 'offer_details');
  }
}
