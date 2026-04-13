import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddWorkPreferenceExtendedFields20260413100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumns('work_preferences', [
      // Safety & Compliance
      new TableColumn({ name: 'min_rest_hours', type: 'smallint', default: 11, isNullable: false }),
      new TableColumn({ name: 'max_consecutive_days', type: 'smallint', default: 5, isNullable: false }),
      new TableColumn({ name: 'max_hours_per_day', type: 'smallint', default: 12, isNullable: false }),
      new TableColumn({ name: 'double_shift_preference', type: 'varchar', length: '20', default: "'sometimes'", isNullable: false }),
      new TableColumn({ name: 'double_shift_conditions', type: 'text', default: "'overtime,emergency'", isNullable: false }),
      // Work Type & Location
      new TableColumn({ name: 'work_type', type: 'varchar', length: '20', default: "'office'", isNullable: false }),
      new TableColumn({ name: 'travel_radius', type: 'smallint', default: 25, isNullable: false }),
      new TableColumn({ name: 'has_own_vehicle', type: 'boolean', default: true, isNullable: false }),
      new TableColumn({ name: 'use_company_vehicle', type: 'boolean', default: false, isNullable: false }),
      new TableColumn({ name: 'preferred_areas', type: 'text', default: "''", isNullable: false }),
      new TableColumn({ name: 'facilities', type: 'jsonb', default: "'{}'", isNullable: false }),
    ]);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const columns = [
      'min_rest_hours', 'max_consecutive_days', 'max_hours_per_day',
      'double_shift_preference', 'double_shift_conditions',
      'work_type', 'travel_radius', 'has_own_vehicle', 'use_company_vehicle',
      'preferred_areas', 'facilities',
    ];
    for (const col of columns) {
      await queryRunner.dropColumn('work_preferences', col);
    }
  }
}
