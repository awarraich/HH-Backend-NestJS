import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddWeeklyNotesToWorkPreferences20260413300000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'work_preferences',
      new TableColumn({
        name: 'weekly_notes',
        type: 'jsonb',
        default: "'{}'",
        isNullable: false,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('work_preferences', 'weekly_notes');
  }
}
