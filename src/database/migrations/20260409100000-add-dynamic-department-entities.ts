import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class AddDynamicDepartmentEntities20260409100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── 1. Column additions to existing tables ──────────────────────────

    // departments: department_head, allow_multi_station_coverage
    const deptTable = await queryRunner.getTable('departments');
    if (deptTable && !deptTable.findColumnByName('department_head')) {
      await queryRunner.query(
        `ALTER TABLE "departments" ADD "department_head" varchar(255) NULL`,
      );
    }
    if (deptTable && !deptTable.findColumnByName('allow_multi_station_coverage')) {
      await queryRunner.query(
        `ALTER TABLE "departments" ADD "allow_multi_station_coverage" boolean NOT NULL DEFAULT false`,
      );
    }

    // rooms: department_id (nullable FK for direct department→room queries)
    const roomsTable = await queryRunner.getTable('rooms');
    if (roomsTable && !roomsTable.findColumnByName('department_id')) {
      await queryRunner.query(
        `ALTER TABLE "rooms" ADD "department_id" uuid NULL`,
      );
      await queryRunner.createForeignKey(
        'rooms',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_rooms_department_id',
        }),
      );
      await queryRunner.createIndex(
        'rooms',
        new TableIndex({
          name: 'idx_rooms_department_id',
          columnNames: ['department_id'],
        }),
      );
    }

    // ── 2. New tables ───────────────────────────────────────────────────

    // zones
    if (!(await queryRunner.hasTable('zones'))) {
      await queryRunner.createTable(
        new Table({
          name: 'zones',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'department_id', type: 'uuid', isNullable: false },
            { name: 'name', type: 'varchar', length: '255', isNullable: false },
            { name: 'area', type: 'varchar', length: '255', isNullable: true },
            { name: 'patient_count', type: 'smallint', default: 0, isNullable: false },
            { name: 'is_active', type: 'boolean', default: true, isNullable: false },
            { name: 'sort_order', type: 'smallint', isNullable: true },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
            { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'zones',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_zones_department_id',
        }),
      );
      await queryRunner.createIndex(
        'zones',
        new TableIndex({ name: 'idx_zones_department_id', columnNames: ['department_id'] }),
      );
    }

    // fleet_vehicles
    if (!(await queryRunner.hasTable('fleet_vehicles'))) {
      await queryRunner.createTable(
        new Table({
          name: 'fleet_vehicles',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'department_id', type: 'uuid', isNullable: false },
            { name: 'name', type: 'varchar', length: '255', isNullable: false },
            { name: 'vehicle_id', type: 'varchar', length: '100', isNullable: true },
            { name: 'vehicle_type', type: 'varchar', length: '50', isNullable: true },
            { name: 'capacity', type: 'smallint', default: 0, isNullable: false },
            { name: 'is_active', type: 'boolean', default: true, isNullable: false },
            { name: 'sort_order', type: 'smallint', isNullable: true },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
            { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'fleet_vehicles',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_fleet_vehicles_department_id',
        }),
      );
      await queryRunner.createIndex(
        'fleet_vehicles',
        new TableIndex({ name: 'idx_fleet_vehicles_department_id', columnNames: ['department_id'] }),
      );
    }

    // lab_workstations
    if (!(await queryRunner.hasTable('lab_workstations'))) {
      await queryRunner.createTable(
        new Table({
          name: 'lab_workstations',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'department_id', type: 'uuid', isNullable: false },
            { name: 'name', type: 'varchar', length: '255', isNullable: false },
            { name: 'equipment', type: 'text', isNullable: true },
            { name: 'workstation_type', type: 'varchar', length: '50', isNullable: true },
            { name: 'is_active', type: 'boolean', default: true, isNullable: false },
            { name: 'sort_order', type: 'smallint', isNullable: true },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
            { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'lab_workstations',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_lab_workstations_department_id',
        }),
      );
      await queryRunner.createIndex(
        'lab_workstations',
        new TableIndex({ name: 'idx_lab_workstations_department_id', columnNames: ['department_id'] }),
      );
    }

    // department_shifts (junction: department ↔ shift)
    if (!(await queryRunner.hasTable('department_shifts'))) {
      await queryRunner.createTable(
        new Table({
          name: 'department_shifts',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'department_id', type: 'uuid', isNullable: false },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_department_shifts', columnNames: ['department_id', 'shift_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'department_shifts',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_department_shifts_department_id',
        }),
      );
      await queryRunner.createForeignKey(
        'department_shifts',
        new TableForeignKey({
          columnNames: ['shift_id'],
          referencedTableName: 'shifts',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_department_shifts_shift_id',
        }),
      );
      await queryRunner.createIndex(
        'department_shifts',
        new TableIndex({ name: 'idx_department_shifts_department_id', columnNames: ['department_id'] }),
      );
      await queryRunner.createIndex(
        'department_shifts',
        new TableIndex({ name: 'idx_department_shifts_shift_id', columnNames: ['shift_id'] }),
      );
    }

    // shift_roles (junction: shift ↔ provider_role)
    if (!(await queryRunner.hasTable('shift_roles'))) {
      await queryRunner.createTable(
        new Table({
          name: 'shift_roles',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'provider_role_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_shift_roles', columnNames: ['shift_id', 'provider_role_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'shift_roles',
        new TableForeignKey({
          columnNames: ['shift_id'],
          referencedTableName: 'shifts',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_shift_roles_shift_id',
        }),
      );
      await queryRunner.createForeignKey(
        'shift_roles',
        new TableForeignKey({
          columnNames: ['provider_role_id'],
          referencedTableName: 'provider_roles',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_shift_roles_provider_role_id',
        }),
      );
      await queryRunner.createIndex(
        'shift_roles',
        new TableIndex({ name: 'idx_shift_roles_shift_id', columnNames: ['shift_id'] }),
      );
    }

    // department_staff
    if (!(await queryRunner.hasTable('department_staff'))) {
      await queryRunner.createTable(
        new Table({
          name: 'department_staff',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'department_id', type: 'uuid', isNullable: false },
            { name: 'staff_type', type: 'varchar', length: '50', isNullable: false },
            { name: 'staff_name', type: 'varchar', length: '100', isNullable: false },
            { name: 'quantity', type: 'smallint', default: 1, isNullable: false },
            { name: 'assignment_level', type: 'varchar', length: '50', isNullable: true },
            { name: 'assignment_type', type: 'varchar', length: '20', isNullable: true },
            { name: 'shift_ids', type: 'jsonb', isNullable: true },
            { name: 'staff_by_shift', type: 'jsonb', isNullable: true },
            { name: 'staff_min_max_by_shift', type: 'jsonb', isNullable: true },
            { name: 'sort_order', type: 'smallint', isNullable: true },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
            { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'department_staff',
        new TableForeignKey({
          columnNames: ['department_id'],
          referencedTableName: 'departments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_department_staff_department_id',
        }),
      );
      await queryRunner.createIndex(
        'department_staff',
        new TableIndex({ name: 'idx_department_staff_department_id', columnNames: ['department_id'] }),
      );
    }

    // ── 3. Entity shift assignment junction tables ───────────────────────

    // station_shift_assignments
    if (!(await queryRunner.hasTable('station_shift_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'station_shift_assignments',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'station_id', type: 'uuid', isNullable: false },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_station_shift_assignments', columnNames: ['station_id', 'shift_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'station_shift_assignments',
        new TableForeignKey({
          columnNames: ['station_id'], referencedTableName: 'stations', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_station_shift_asgn_station_id',
        }),
      );
      await queryRunner.createForeignKey(
        'station_shift_assignments',
        new TableForeignKey({
          columnNames: ['shift_id'], referencedTableName: 'shifts', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_station_shift_asgn_shift_id',
        }),
      );
    }

    // room_shift_assignments
    if (!(await queryRunner.hasTable('room_shift_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'room_shift_assignments',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'room_id', type: 'uuid', isNullable: false },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_room_shift_assignments', columnNames: ['room_id', 'shift_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'room_shift_assignments',
        new TableForeignKey({
          columnNames: ['room_id'], referencedTableName: 'rooms', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_room_shift_asgn_room_id',
        }),
      );
      await queryRunner.createForeignKey(
        'room_shift_assignments',
        new TableForeignKey({
          columnNames: ['shift_id'], referencedTableName: 'shifts', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_room_shift_asgn_shift_id',
        }),
      );
    }

    // zone_shift_assignments
    if (!(await queryRunner.hasTable('zone_shift_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'zone_shift_assignments',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'zone_id', type: 'uuid', isNullable: false },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_zone_shift_assignments', columnNames: ['zone_id', 'shift_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'zone_shift_assignments',
        new TableForeignKey({
          columnNames: ['zone_id'], referencedTableName: 'zones', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_zone_shift_asgn_zone_id',
        }),
      );
      await queryRunner.createForeignKey(
        'zone_shift_assignments',
        new TableForeignKey({
          columnNames: ['shift_id'], referencedTableName: 'shifts', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_zone_shift_asgn_shift_id',
        }),
      );
    }

    // vehicle_shift_assignments
    if (!(await queryRunner.hasTable('vehicle_shift_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'vehicle_shift_assignments',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'vehicle_id', type: 'uuid', isNullable: false },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_vehicle_shift_assignments', columnNames: ['vehicle_id', 'shift_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'vehicle_shift_assignments',
        new TableForeignKey({
          columnNames: ['vehicle_id'], referencedTableName: 'fleet_vehicles', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_vehicle_shift_asgn_vehicle_id',
        }),
      );
      await queryRunner.createForeignKey(
        'vehicle_shift_assignments',
        new TableForeignKey({
          columnNames: ['shift_id'], referencedTableName: 'shifts', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_vehicle_shift_asgn_shift_id',
        }),
      );
    }

    // workstation_shift_assignments
    if (!(await queryRunner.hasTable('workstation_shift_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'workstation_shift_assignments',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'workstation_id', type: 'uuid', isNullable: false },
            { name: 'shift_id', type: 'uuid', isNullable: false },
            { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          ],
          uniques: [
            new TableUnique({ name: 'uq_workstation_shift_assignments', columnNames: ['workstation_id', 'shift_id'] }),
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'workstation_shift_assignments',
        new TableForeignKey({
          columnNames: ['workstation_id'], referencedTableName: 'lab_workstations', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_workstation_shift_asgn_workstation_id',
        }),
      );
      await queryRunner.createForeignKey(
        'workstation_shift_assignments',
        new TableForeignKey({
          columnNames: ['shift_id'], referencedTableName: 'shifts', referencedColumnNames: ['id'],
          onDelete: 'CASCADE', name: 'fk_workstation_shift_asgn_shift_id',
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop junction tables (reverse order)
    const junctionTables = [
      'workstation_shift_assignments',
      'vehicle_shift_assignments',
      'zone_shift_assignments',
      'room_shift_assignments',
      'station_shift_assignments',
    ];
    for (const table of junctionTables) {
      if (await queryRunner.hasTable(table)) {
        await queryRunner.dropTable(table, true, true);
      }
    }

    // Drop entity tables
    const entityTables = [
      'department_staff',
      'shift_roles',
      'department_shifts',
      'lab_workstations',
      'fleet_vehicles',
      'zones',
    ];
    for (const table of entityTables) {
      if (await queryRunner.hasTable(table)) {
        await queryRunner.dropTable(table, true, true);
      }
    }

    // Drop added columns
    const roomsTable = await queryRunner.getTable('rooms');
    if (roomsTable?.findColumnByName('department_id')) {
      await queryRunner.dropForeignKey('rooms', 'fk_rooms_department_id');
      await queryRunner.dropIndex('rooms', 'idx_rooms_department_id');
      await queryRunner.dropColumn('rooms', 'department_id');
    }

    const deptTable = await queryRunner.getTable('departments');
    if (deptTable?.findColumnByName('allow_multi_station_coverage')) {
      await queryRunner.dropColumn('departments', 'allow_multi_station_coverage');
    }
    if (deptTable?.findColumnByName('department_head')) {
      await queryRunner.dropColumn('departments', 'department_head');
    }
  }
}
