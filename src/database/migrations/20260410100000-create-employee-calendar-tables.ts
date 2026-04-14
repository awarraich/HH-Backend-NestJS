import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class CreateEmployeeCalendarTables20260410100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── 1. calendar_events ─────────────────────────────────────────────
    await queryRunner.createTable(
      new Table({
        name: 'calendar_events',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: true },
          { name: 'title', type: 'varchar', length: '255', isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'start_at', type: 'timestamp with time zone', isNullable: false },
          { name: 'end_at', type: 'timestamp with time zone', isNullable: false },
          { name: 'all_day', type: 'boolean', default: false, isNullable: false },
          { name: 'location', type: 'varchar', length: '500', isNullable: true },
          { name: 'event_type', type: 'varchar', length: '50', default: "'general'", isNullable: false },
          { name: 'color', type: 'varchar', length: '20', isNullable: true },
          { name: 'recurrence_rule', type: 'varchar', length: '255', isNullable: true },
          { name: 'recurrence_end_date', type: 'date', isNullable: true },
          { name: 'timezone', type: 'varchar', length: '100', default: "'UTC'", isNullable: false },
          { name: 'status', type: 'varchar', length: '20', default: "'active'", isNullable: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'calendar_events',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_calendar_events_user_id',
      }),
    );
    await queryRunner.createForeignKey(
      'calendar_events',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_calendar_events_organization_id',
      }),
    );
    await queryRunner.createIndex(
      'calendar_events',
      new TableIndex({ name: 'idx_calendar_events_user_id', columnNames: ['user_id'] }),
    );
    await queryRunner.createIndex(
      'calendar_events',
      new TableIndex({ name: 'idx_calendar_events_org_id', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'calendar_events',
      new TableIndex({ name: 'idx_calendar_events_user_start', columnNames: ['user_id', 'start_at'] }),
    );
    await queryRunner.createIndex(
      'calendar_events',
      new TableIndex({ name: 'idx_calendar_events_status', columnNames: ['status'] }),
    );

    // ── 2. availability_rules ──────────────────────────────────────────
    await queryRunner.createTable(
      new Table({
        name: 'availability_rules',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: true },
          { name: 'day_of_week', type: 'smallint', isNullable: false },
          { name: 'start_time', type: 'time', isNullable: false },
          { name: 'end_time', type: 'time', isNullable: false },
          { name: 'is_available', type: 'boolean', default: true, isNullable: false },
          { name: 'shift_type', type: 'varchar', length: '50', isNullable: true },
          { name: 'effective_from', type: 'date', isNullable: true },
          { name: 'effective_until', type: 'date', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'availability_rules',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_availability_rules_user_id',
      }),
    );
    await queryRunner.createForeignKey(
      'availability_rules',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_availability_rules_organization_id',
      }),
    );
    await queryRunner.createIndex(
      'availability_rules',
      new TableIndex({ name: 'idx_availability_rules_user_id', columnNames: ['user_id'] }),
    );
    await queryRunner.createIndex(
      'availability_rules',
      new TableIndex({ name: 'idx_availability_rules_org_id', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'availability_rules',
      new TableIndex({ name: 'idx_availability_rules_user_day', columnNames: ['user_id', 'day_of_week'] }),
    );

    // ── 3. time_off_requests ───────────────────────────────────────────
    await queryRunner.createTable(
      new Table({
        name: 'time_off_requests',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: true },
          { name: 'start_date', type: 'date', isNullable: false },
          { name: 'end_date', type: 'date', isNullable: false },
          { name: 'reason', type: 'text', isNullable: true },
          { name: 'status', type: 'varchar', length: '20', default: "'pending'", isNullable: false },
          { name: 'reviewed_by', type: 'uuid', isNullable: true },
          { name: 'reviewed_at', type: 'timestamp with time zone', isNullable: true },
          { name: 'review_notes', type: 'text', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'time_off_requests',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_time_off_requests_user_id',
      }),
    );
    await queryRunner.createForeignKey(
      'time_off_requests',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_time_off_requests_organization_id',
      }),
    );
    await queryRunner.createForeignKey(
      'time_off_requests',
      new TableForeignKey({
        columnNames: ['reviewed_by'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_time_off_requests_reviewed_by',
      }),
    );
    await queryRunner.createIndex(
      'time_off_requests',
      new TableIndex({ name: 'idx_time_off_requests_user_id', columnNames: ['user_id'] }),
    );
    await queryRunner.createIndex(
      'time_off_requests',
      new TableIndex({ name: 'idx_time_off_requests_org_id', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'time_off_requests',
      new TableIndex({ name: 'idx_time_off_requests_status', columnNames: ['status'] }),
    );
    await queryRunner.createIndex(
      'time_off_requests',
      new TableIndex({ name: 'idx_time_off_requests_user_dates', columnNames: ['user_id', 'start_date', 'end_date'] }),
    );

    // ── 4. work_preferences ────────────────────────────────────────────
    await queryRunner.createTable(
      new Table({
        name: 'work_preferences',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'user_id', type: 'uuid', isNullable: false, isUnique: true },
          { name: 'max_hours_per_week', type: 'smallint', default: 40, isNullable: false },
          { name: 'preferred_shift_type', type: 'varchar', length: '50', default: "'morning'", isNullable: false },
          { name: 'available_for_overtime', type: 'boolean', default: false, isNullable: false },
          { name: 'available_for_on_call', type: 'boolean', default: false, isNullable: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'work_preferences',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_work_preferences_user_id',
      }),
    );
    await queryRunner.createIndex(
      'work_preferences',
      new TableIndex({ name: 'idx_work_preferences_user_id', columnNames: ['user_id'] }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('work_preferences', true);
    await queryRunner.dropTable('time_off_requests', true);
    await queryRunner.dropTable('availability_rules', true);
    await queryRunner.dropTable('calendar_events', true);
  }
}
