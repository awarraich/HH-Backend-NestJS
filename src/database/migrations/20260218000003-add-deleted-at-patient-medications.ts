import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddDeletedAtPatientMedications20260218000003
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'patient_medications',
      new TableColumn({
        name: 'deleted_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('patient_medications', 'deleted_at');
  }
}
