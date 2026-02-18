import { MigrationInterface, QueryRunner, TableColumn, TableForeignKey } from 'typeorm';

export class AddRecordedByToMedicationAdministrations20260218000002
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'medication_administrations',
      new TableColumn({
        name: 'recorded_by_user_id',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.createForeignKey(
      'medication_administrations',
      new TableForeignKey({
        columnNames: ['recorded_by_user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_medication_administrations_recorded_by_user_id',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropForeignKey(
      'medication_administrations',
      'fk_medication_administrations_recorded_by_user_id',
    );
    await queryRunner.dropColumn('medication_administrations', 'recorded_by_user_id');
  }
}
