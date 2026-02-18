import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
} from 'typeorm';

export class CreatePatientMedicationsTables20260218000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'patient_medications',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'patient_id', type: 'uuid', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: false },
          { name: 'dosage', type: 'varchar', length: '100', isNullable: true },
          { name: 'form', type: 'varchar', length: '50', isNullable: true },
          { name: 'frequency', type: 'varchar', length: '100', isNullable: true },
          { name: 'prescribed_by', type: 'varchar', length: '255', isNullable: true },
          { name: 'instructions', type: 'text', isNullable: true },
          { name: 'start_date', type: 'date', isNullable: true },
          { name: 'on_hand', type: 'int', isNullable: false, default: 0 },
          { name: 'total_quantity', type: 'int', isNullable: false, default: 1 },
          { name: 'unit', type: 'varchar', length: '50', isNullable: true },
          { name: 'created_at', type: 'timestamptz', default: 'CURRENT_TIMESTAMP' },
          { name: 'updated_at', type: 'timestamptz', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'patient_medications',
      new TableForeignKey({
        columnNames: ['patient_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_patient_medications_patient_id',
      }),
    );

    await queryRunner.createIndex(
      'patient_medications',
      new TableIndex({ name: 'idx_patient_medications_patient_id', columnNames: ['patient_id'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'patient_medication_time_slots',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'patient_medication_id', type: 'uuid', isNullable: false },
          { name: 'time_of_day', type: 'varchar', length: '20', isNullable: true },
          { name: 'sort_order', type: 'smallint', isNullable: false, default: 0 },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'patient_medication_time_slots',
      new TableForeignKey({
        columnNames: ['patient_medication_id'],
        referencedTableName: 'patient_medications',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_patient_medication_time_slots_medication_id',
      }),
    );

    await queryRunner.createIndex(
      'patient_medication_time_slots',
      new TableIndex({
        name: 'idx_patient_medication_time_slots_medication_id',
        columnNames: ['patient_medication_id'],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'medication_administrations',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'patient_medication_id', type: 'uuid', isNullable: false },
          { name: 'scheduled_date', type: 'date', isNullable: false },
          { name: 'time_slot', type: 'varchar', length: '20', isNullable: true },
          { name: 'taken', type: 'boolean', isNullable: false, default: false },
          { name: 'taken_at', type: 'timestamptz', isNullable: true },
          { name: 'method', type: 'varchar', length: '20', isNullable: true },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'medication_administrations',
      new TableForeignKey({
        columnNames: ['patient_medication_id'],
        referencedTableName: 'patient_medications',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_medication_administrations_medication_id',
      }),
    );

    await queryRunner.createIndex(
      'medication_administrations',
      new TableIndex({
        name: 'idx_medication_administrations_medication_date',
        columnNames: ['patient_medication_id', 'scheduled_date'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('medication_administrations');
    await queryRunner.dropTable('patient_medication_time_slots');
    await queryRunner.dropTable('patient_medications');
  }
}
