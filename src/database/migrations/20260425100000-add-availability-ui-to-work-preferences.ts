import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Per-org availability UI state (which preset chip is active, the
 * 4-on-2-off rotation start date + shift toggles) piggy-backs on the
 * existing `work_preferences` row rather than getting its own table.
 * The work-preferences row already round-trips on every save and the
 * payload is small opaque JSON — one column keeps the writes atomic
 * with the rest of the preferences bundle and avoids another endpoint.
 */
export class AddAvailabilityUiToWorkPreferences20260425100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'work_preferences',
      new TableColumn({
        name: 'availability_ui_by_org',
        type: 'jsonb',
        isNullable: false,
        default: "'{}'::jsonb",
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('work_preferences', 'availability_ui_by_org');
  }
}
