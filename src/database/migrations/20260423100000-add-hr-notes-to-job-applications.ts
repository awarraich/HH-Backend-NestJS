import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddHrNotesToJobApplications20260423100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'job_applications',
      new TableColumn({
        name: 'hr_notes',
        type: 'text',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('job_applications', 'hr_notes');
  }
}
