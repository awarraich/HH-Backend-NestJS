import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableIndex,
} from 'typeorm';

export class AddDateToAvailabilityRules20260410200000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('availability_rules');

    // 1. Add nullable `date` column for specific-date availability
    if (!table?.findColumnByName('date')) {
      await queryRunner.addColumn(
        'availability_rules',
        new TableColumn({
          name: 'date',
          type: 'date',
          isNullable: true,
        }),
      );
    }

    // 2. Make day_of_week nullable (not needed for date-specific rules)
    const dayOfWeekCol = table?.findColumnByName('day_of_week');
    if (dayOfWeekCol && !dayOfWeekCol.isNullable) {
      await queryRunner.changeColumn(
        'availability_rules',
        'day_of_week',
        new TableColumn({
          name: 'day_of_week',
          type: 'smallint',
          isNullable: true,
        }),
      );
    }

    // 3. Add index for date-based lookups
    const hasIndex = table?.indices.some(
      (idx) => idx.name === 'idx_availability_rules_user_date',
    );
    if (!hasIndex) {
      await queryRunner.createIndex(
        'availability_rules',
        new TableIndex({
          name: 'idx_availability_rules_user_date',
          columnNames: ['user_id', 'date'],
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'availability_rules',
      'idx_availability_rules_user_date',
    );

    await queryRunner.changeColumn(
      'availability_rules',
      'day_of_week',
      new TableColumn({
        name: 'day_of_week',
        type: 'smallint',
        isNullable: false,
      }),
    );

    await queryRunner.dropColumn('availability_rules', 'date');
  }
}
