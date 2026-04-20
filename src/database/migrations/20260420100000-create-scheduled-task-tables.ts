import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
  TableUnique,
} from 'typeorm';

/**
 * Polymorphic scheduled-task model that powers the org-type-specific scheduling
 * views (clinic appointments, transportation trips, pharmacy prescriptions,
 * field visits). A core `scheduled_tasks` row is discriminated by
 * `task_type_code` (looked up in `scheduling_task_types`) and carries a JSONB
 * `details` payload for view-specific fields — so new task types can be added
 * via a new row in `scheduling_task_types` without schema changes.
 *
 * Existing `shifts` / `employee_shifts` are NOT touched. `scheduled_tasks`
 * may optionally reference a `shift_id`; assignments may optionally reference
 * an `employee_shift_id` to bridge to the existing scheduling model.
 */
export class CreateScheduledTaskTables20260420100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── scheduling_task_types (registry) ──────────────────────────────────────
    if (!(await queryRunner.getTable('scheduling_task_types'))) {
      await queryRunner.createTable(
        new Table({
          name: 'scheduling_task_types',
          columns: [
            {
              name: 'code',
              type: 'varchar',
              length: '64',
              isPrimary: true,
              isNullable: false,
            },
            { name: 'label', type: 'varchar', length: '128', isNullable: false },
            {
              name: 'organization_type_keys',
              type: 'jsonb',
              default: "'[]'::jsonb",
              isNullable: false,
            },
            {
              name: 'default_statuses',
              type: 'jsonb',
              default: "'{}'::jsonb",
              isNullable: false,
            },
            {
              name: 'resource_schema',
              type: 'jsonb',
              default: "'{}'::jsonb",
              isNullable: false,
            },
            {
              name: 'details_schema',
              type: 'jsonb',
              default: "'{}'::jsonb",
              isNullable: false,
            },
            {
              name: 'is_active',
              type: 'boolean',
              default: true,
              isNullable: false,
            },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
            {
              name: 'updated_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
          ],
        }),
        true,
      );
    }

    // ── scheduled_tasks ───────────────────────────────────────────────────────
    if (!(await queryRunner.getTable('scheduled_tasks'))) {
      await queryRunner.createTable(
        new Table({
          name: 'scheduled_tasks',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'gen_random_uuid()',
            },
            { name: 'organization_id', type: 'uuid', isNullable: false },
            {
              name: 'task_type_code',
              type: 'varchar',
              length: '64',
              isNullable: false,
            },
            {
              name: 'status',
              type: 'varchar',
              length: '32',
              default: "'scheduled'",
              isNullable: false,
            },
            {
              name: 'priority',
              type: 'smallint',
              default: 2,
              isNullable: false,
            },
            {
              name: 'scheduled_start_at',
              type: 'timestamptz',
              isNullable: false,
            },
            {
              name: 'scheduled_end_at',
              type: 'timestamptz',
              isNullable: false,
            },
            {
              name: 'actual_start_at',
              type: 'timestamptz',
              isNullable: true,
            },
            { name: 'actual_end_at', type: 'timestamptz', isNullable: true },
            { name: 'department_id', type: 'uuid', isNullable: true },
            { name: 'station_id', type: 'uuid', isNullable: true },
            { name: 'room_id', type: 'uuid', isNullable: true },
            { name: 'bed_id', type: 'uuid', isNullable: true },
            { name: 'chair_id', type: 'uuid', isNullable: true },
            { name: 'zone_id', type: 'uuid', isNullable: true },
            { name: 'fleet_vehicle_id', type: 'uuid', isNullable: true },
            { name: 'lab_workstation_id', type: 'uuid', isNullable: true },
            { name: 'shift_id', type: 'uuid', isNullable: true },
            {
              name: 'subject_name',
              type: 'varchar',
              length: '255',
              isNullable: true,
            },
            {
              name: 'subject_phone',
              type: 'varchar',
              length: '64',
              isNullable: true,
            },
            { name: 'subject_address', type: 'text', isNullable: true },
            { name: 'notes', type: 'text', isNullable: true },
            {
              name: 'details',
              type: 'jsonb',
              default: "'{}'::jsonb",
              isNullable: false,
            },
            { name: 'created_by', type: 'uuid', isNullable: true },
            { name: 'updated_by', type: 'uuid', isNullable: true },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
            {
              name: 'updated_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
            { name: 'deleted_at', type: 'timestamptz', isNullable: true },
          ],
        }),
        true,
      );

      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['organization_id'],
          referencedTableName: 'organizations',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_scheduled_tasks_organization',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['task_type_code'],
          referencedTableName: 'scheduling_task_types',
          referencedColumnNames: ['code'],
          onDelete: 'RESTRICT',
          name: 'fk_scheduled_tasks_task_type',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['station_id'],
          referencedTableName: 'stations',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['room_id'],
          referencedTableName: 'rooms',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['bed_id'],
          referencedTableName: 'beds',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['chair_id'],
          referencedTableName: 'chairs',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['zone_id'],
          referencedTableName: 'zones',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['fleet_vehicle_id'],
          referencedTableName: 'fleet_vehicles',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['lab_workstation_id'],
          referencedTableName: 'lab_workstations',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_tasks',
        new TableForeignKey({
          columnNames: ['shift_id'],
          referencedTableName: 'shifts',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );

      await queryRunner.createIndex(
        'scheduled_tasks',
        new TableIndex({
          name: 'idx_scheduled_tasks_org_type_start',
          columnNames: ['organization_id', 'task_type_code', 'scheduled_start_at'],
        }),
      );
      await queryRunner.createIndex(
        'scheduled_tasks',
        new TableIndex({
          name: 'idx_scheduled_tasks_org_type_status',
          columnNames: ['organization_id', 'task_type_code', 'status'],
        }),
      );
      await queryRunner.createIndex(
        'scheduled_tasks',
        new TableIndex({
          name: 'idx_scheduled_tasks_start_at',
          columnNames: ['scheduled_start_at'],
        }),
      );

      // GIN index on details for future querying by task-specific fields.
      await queryRunner.query(
        `CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_details_gin ON scheduled_tasks USING GIN (details)`,
      );
    }

    // ── scheduled_task_assignments ────────────────────────────────────────────
    if (!(await queryRunner.getTable('scheduled_task_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'scheduled_task_assignments',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'gen_random_uuid()',
            },
            { name: 'scheduled_task_id', type: 'uuid', isNullable: false },
            { name: 'employee_id', type: 'uuid', isNullable: false },
            { name: 'employee_shift_id', type: 'uuid', isNullable: true },
            {
              name: 'assignment_role',
              type: 'varchar',
              length: '64',
              isNullable: false,
            },
            {
              name: 'is_primary',
              type: 'boolean',
              default: true,
              isNullable: false,
            },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
            {
              name: 'updated_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
          ],
        }),
        true,
      );

      await queryRunner.createForeignKey(
        'scheduled_task_assignments',
        new TableForeignKey({
          columnNames: ['scheduled_task_id'],
          referencedTableName: 'scheduled_tasks',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_task_assignments',
        new TableForeignKey({
          columnNames: ['employee_id'],
          referencedTableName: 'employees',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
      await queryRunner.createForeignKey(
        'scheduled_task_assignments',
        new TableForeignKey({
          columnNames: ['employee_shift_id'],
          referencedTableName: 'employee_shifts',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
      await queryRunner.createIndex(
        'scheduled_task_assignments',
        new TableIndex({
          name: 'idx_sta_scheduled_task',
          columnNames: ['scheduled_task_id'],
        }),
      );
      await queryRunner.createIndex(
        'scheduled_task_assignments',
        new TableIndex({
          name: 'idx_sta_employee',
          columnNames: ['employee_id'],
        }),
      );
      await queryRunner.createUniqueConstraint(
        'scheduled_task_assignments',
        new TableUnique({
          name: 'uq_sta_task_employee_role',
          columnNames: ['scheduled_task_id', 'employee_id', 'assignment_role'],
        }),
      );
    }

    // ── scheduled_task_status_history ─────────────────────────────────────────
    if (!(await queryRunner.getTable('scheduled_task_status_history'))) {
      await queryRunner.createTable(
        new Table({
          name: 'scheduled_task_status_history',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'gen_random_uuid()',
            },
            { name: 'scheduled_task_id', type: 'uuid', isNullable: false },
            {
              name: 'from_status',
              type: 'varchar',
              length: '32',
              isNullable: true,
            },
            {
              name: 'to_status',
              type: 'varchar',
              length: '32',
              isNullable: false,
            },
            { name: 'changed_by', type: 'uuid', isNullable: true },
            {
              name: 'changed_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
              isNullable: false,
            },
            { name: 'reason', type: 'text', isNullable: true },
          ],
        }),
        true,
      );

      await queryRunner.createForeignKey(
        'scheduled_task_status_history',
        new TableForeignKey({
          columnNames: ['scheduled_task_id'],
          referencedTableName: 'scheduled_tasks',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
      await queryRunner.createIndex(
        'scheduled_task_status_history',
        new TableIndex({
          name: 'idx_stsh_scheduled_task',
          columnNames: ['scheduled_task_id'],
        }),
      );
    }

    // ── Seed the 4 initial task types ─────────────────────────────────────────
    const seeds: Array<{
      code: string;
      label: string;
      organization_type_keys: string[];
      default_statuses: Record<string, unknown>;
      resource_schema: Record<string, unknown>;
      details_schema: Record<string, unknown>;
    }> = [
      {
        code: 'clinic_appointment',
        label: 'Clinic Appointment',
        organization_type_keys: ['clinic'],
        default_statuses: {
          initial: 'scheduled',
          allowed: [
            'scheduled',
            'checked-in',
            'in-progress',
            'completed',
            'cancelled',
            'no-show',
          ],
          terminal: ['completed', 'cancelled', 'no-show'],
        },
        resource_schema: {
          department_id: 'optional',
          room_id: 'optional',
          shift_id: 'optional',
        },
        details_schema: {
          appointment_type: { type: 'string', required: true },
          chief_complaint: { type: 'string', required: false },
          insurance_provider: { type: 'string', required: false },
          patient_date_of_birth: { type: 'date', required: false },
          duration_minutes: { type: 'integer', required: false },
        },
      },
      {
        code: 'transport_trip',
        label: 'Transportation Trip',
        organization_type_keys: ['transport', 'transportation'],
        default_statuses: {
          initial: 'scheduled',
          allowed: [
            'scheduled',
            'en-route-pickup',
            'picked-up',
            'en-route-dropoff',
            'completed',
            'cancelled',
          ],
          terminal: ['completed', 'cancelled'],
        },
        resource_schema: {
          department_id: 'optional',
          fleet_vehicle_id: 'optional',
        },
        details_schema: {
          pickup_address: { type: 'string', required: true },
          dropoff_address: { type: 'string', required: true },
          trip_type: { type: 'string', required: false },
          vehicle_type: { type: 'string', required: false },
          special_needs: { type: 'array', required: false },
        },
      },
      {
        code: 'pharmacy_prescription',
        label: 'Pharmacy Prescription',
        organization_type_keys: ['pharmacy', 'pharm'],
        default_statuses: {
          initial: 'received',
          allowed: [
            'received',
            'in-progress',
            'quality-check',
            'ready-for-pickup',
            'dispensed',
            'on-hold',
            'cancelled',
          ],
          terminal: ['dispensed', 'cancelled'],
        },
        resource_schema: {
          department_id: 'optional',
          station_id: 'optional',
          lab_workstation_id: 'optional',
        },
        details_schema: {
          medication: { type: 'string', required: true },
          dosage: { type: 'string', required: false },
          quantity: { type: 'integer', required: false },
          prescribed_by: { type: 'string', required: false },
          allergies: { type: 'string', required: false },
          instructions: { type: 'string', required: false },
          priority_level: { type: 'string', required: false },
        },
      },
      {
        code: 'field_visit',
        label: 'Field Visit',
        organization_type_keys: ['home health', 'hospice', 'field'],
        default_statuses: {
          initial: 'scheduled',
          allowed: [
            'scheduled',
            'en-route',
            'in-progress',
            'completed',
            'no-show',
            'cancelled',
          ],
          terminal: ['completed', 'cancelled', 'no-show'],
        },
        resource_schema: {
          department_id: 'optional',
          zone_id: 'optional',
        },
        details_schema: {
          visit_type: { type: 'string', required: true },
          duration_minutes: { type: 'integer', required: false },
          time_window_start: { type: 'string', required: false },
          time_window_end: { type: 'string', required: false },
        },
      },
    ];

    for (const s of seeds) {
      await queryRunner.query(
        `INSERT INTO scheduling_task_types
          (code, label, organization_type_keys, default_statuses, resource_schema, details_schema, is_active)
         VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb, true)
         ON CONFLICT (code) DO NOTHING`,
        [
          s.code,
          s.label,
          JSON.stringify(s.organization_type_keys),
          JSON.stringify(s.default_statuses),
          JSON.stringify(s.resource_schema),
          JSON.stringify(s.details_schema),
        ],
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('scheduled_task_status_history', true);
    await queryRunner.dropTable('scheduled_task_assignments', true);
    await queryRunner.query(
      `DROP INDEX IF EXISTS idx_scheduled_tasks_details_gin`,
    );
    await queryRunner.dropTable('scheduled_tasks', true);
    await queryRunner.dropTable('scheduling_task_types', true);
  }
}
