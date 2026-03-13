import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateSchedulingTables20260316000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'departments',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: false },
          { name: 'code', type: 'varchar', length: '50', isNullable: true },
          { name: 'is_active', type: 'boolean', default: true, isNullable: false },
          { name: 'sort_order', type: 'smallint', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );
    await queryRunner.createIndex('departments', new TableIndex({ name: 'idx_departments_organization_id', columnNames: ['organization_id'] }));
    await queryRunner.createIndex('departments', new TableIndex({ name: 'idx_departments_org_active', columnNames: ['organization_id', 'is_active'] }));
    await queryRunner.createForeignKey(
      'departments',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_departments_organization_id',
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'stations',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'department_id', type: 'uuid', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: false },
          { name: 'code', type: 'varchar', length: '50', isNullable: true },
          { name: 'is_active', type: 'boolean', default: true, isNullable: false },
          { name: 'sort_order', type: 'smallint', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );
    await queryRunner.createIndex('stations', new TableIndex({ name: 'idx_stations_department_id', columnNames: ['department_id'] }));
    await queryRunner.createIndex('stations', new TableIndex({ name: 'idx_stations_dept_active', columnNames: ['department_id', 'is_active'] }));
    await queryRunner.createForeignKey(
      'stations',
      new TableForeignKey({
        columnNames: ['department_id'],
        referencedTableName: 'departments',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_stations_department_id',
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'rooms',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'station_id', type: 'uuid', isNullable: false },
          { name: 'name', type: 'varchar', length: '100', isNullable: false },
          { name: 'is_active', type: 'boolean', default: true, isNullable: false },
          { name: 'sort_order', type: 'smallint', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );
    await queryRunner.createIndex('rooms', new TableIndex({ name: 'idx_rooms_station_id', columnNames: ['station_id'] }));
    await queryRunner.createIndex('rooms', new TableIndex({ name: 'idx_rooms_station_active', columnNames: ['station_id', 'is_active'] }));
    await queryRunner.createForeignKey(
      'rooms',
      new TableForeignKey({
        columnNames: ['station_id'],
        referencedTableName: 'stations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_rooms_station_id',
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'beds',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'room_id', type: 'uuid', isNullable: false },
          { name: 'bed_number', type: 'varchar', length: '50', isNullable: false },
          { name: 'is_active', type: 'boolean', default: true, isNullable: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );
    await queryRunner.createIndex('beds', new TableIndex({ name: 'idx_beds_room_id', columnNames: ['room_id'] }));
    await queryRunner.createIndex('beds', new TableIndex({ name: 'idx_beds_room_active', columnNames: ['room_id', 'is_active'] }));
    await queryRunner.createForeignKey(
      'beds',
      new TableForeignKey({
        columnNames: ['room_id'],
        referencedTableName: 'rooms',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_beds_room_id',
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'shifts',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'start_at', type: 'timestamp', isNullable: false },
          { name: 'end_at', type: 'timestamp', isNullable: false },
          { name: 'shift_type', type: 'varchar', length: '50', isNullable: true },
          { name: 'name', type: 'varchar', length: '255', isNullable: true },
          { name: 'status', type: 'varchar', length: '20', default: "'ACTIVE'", isNullable: false },
          { name: 'recurrence_type', type: 'varchar', length: '20', default: "'ONE_TIME'", isNullable: false },
          { name: 'recurrence_days', type: 'varchar', length: '50', isNullable: true },
          { name: 'recurrence_start_date', type: 'date', isNullable: true },
          { name: 'recurrence_end_date', type: 'date', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );
    await queryRunner.createIndex('shifts', new TableIndex({ name: 'idx_shifts_organization_id', columnNames: ['organization_id'] }));
    await queryRunner.createIndex('shifts', new TableIndex({ name: 'idx_shifts_org_start_at', columnNames: ['organization_id', 'start_at'] }));
    await queryRunner.createIndex('shifts', new TableIndex({ name: 'idx_shifts_org_status', columnNames: ['organization_id', 'status'] }));
    await queryRunner.createForeignKey(
      'shifts',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_shifts_organization_id',
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'employee_shifts',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'shift_id', type: 'uuid', isNullable: false },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          { name: 'department_id', type: 'uuid', isNullable: true },
          { name: 'station_id', type: 'uuid', isNullable: true },
          { name: 'room_id', type: 'uuid', isNullable: true },
          { name: 'bed_id', type: 'uuid', isNullable: true },
          { name: 'status', type: 'varchar', length: '20', default: "'SCHEDULED'", isNullable: false },
          { name: 'notes', type: 'text', isNullable: true },
          { name: 'actual_start_at', type: 'timestamp', isNullable: true },
          { name: 'actual_end_at', type: 'timestamp', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );
    await queryRunner.createUniqueConstraint(
      'employee_shifts',
      new TableUnique({ name: 'uq_employee_shifts_shift_employee', columnNames: ['shift_id', 'employee_id'] }),
    );
    await queryRunner.createIndex('employee_shifts', new TableIndex({ name: 'idx_employee_shifts_shift_id', columnNames: ['shift_id'] }));
    await queryRunner.createIndex('employee_shifts', new TableIndex({ name: 'idx_employee_shifts_employee_id', columnNames: ['employee_id'] }));
    await queryRunner.createIndex('employee_shifts', new TableIndex({ name: 'idx_employee_shifts_employee_status', columnNames: ['employee_id', 'status'] }));
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['shift_id'],
        referencedTableName: 'shifts',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_shifts_shift_id',
      }),
    );
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_shifts_employee_id',
      }),
    );
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['department_id'],
        referencedTableName: 'departments',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employee_shifts_department_id',
      }),
    );
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['station_id'],
        referencedTableName: 'stations',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employee_shifts_station_id',
      }),
    );
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['room_id'],
        referencedTableName: 'rooms',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employee_shifts_room_id',
      }),
    );
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['bed_id'],
        referencedTableName: 'beds',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employee_shifts_bed_id',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('employee_shifts', true);
    await queryRunner.dropTable('shifts', true);
    await queryRunner.dropTable('beds', true);
    await queryRunner.dropTable('rooms', true);
    await queryRunner.dropTable('stations', true);
    await queryRunner.dropTable('departments', true);
  }
}
