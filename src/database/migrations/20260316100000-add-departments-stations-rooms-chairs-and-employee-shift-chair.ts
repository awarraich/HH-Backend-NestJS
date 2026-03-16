import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class AddDepartmentsStationsRoomsChairsAndEmployeeShiftChair20260316100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'departments',
      new TableColumn({
        name: 'description',
        type: 'text',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'departments',
      new TableColumn({
        name: 'department_type',
        type: 'varchar',
        length: '50',
        isNullable: true,
      }),
    );

    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'location',
        type: 'varchar',
        length: '255',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'required_charge_nurses',
        type: 'smallint',
        default: 0,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'required_cnas',
        type: 'smallint',
        default: 0,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'required_sitters',
        type: 'smallint',
        default: 0,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'required_treatment_nurses',
        type: 'smallint',
        default: 0,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'required_nps',
        type: 'smallint',
        default: 0,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'required_mds',
        type: 'smallint',
        default: 0,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'multi_station_am',
        type: 'boolean',
        default: false,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'multi_station_pm',
        type: 'boolean',
        default: false,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'multi_station_noc',
        type: 'boolean',
        default: false,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'configuration_type',
        type: 'varchar',
        length: '20',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'default_beds_per_room',
        type: 'smallint',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'default_chairs_per_room',
        type: 'smallint',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'stations',
      new TableColumn({
        name: 'custom_shift_times',
        type: 'jsonb',
        isNullable: true,
      }),
    );

    await queryRunner.addColumn(
      'rooms',
      new TableColumn({
        name: 'location_or_wing',
        type: 'varchar',
        length: '255',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'rooms',
      new TableColumn({
        name: 'floor',
        type: 'varchar',
        length: '50',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'rooms',
      new TableColumn({
        name: 'configuration_type',
        type: 'varchar',
        length: '20',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'rooms',
      new TableColumn({
        name: 'beds_per_room',
        type: 'smallint',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'rooms',
      new TableColumn({
        name: 'chairs_per_room',
        type: 'smallint',
        isNullable: true,
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'chairs',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'room_id', type: 'uuid', isNullable: false },
          {
            name: 'chair_number',
            type: 'varchar',
            length: '50',
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
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
        ],
      }),
      true,
    );
    await queryRunner.createIndex(
      'chairs',
      new TableIndex({
        name: 'idx_chairs_room_id',
        columnNames: ['room_id'],
      }),
    );
    await queryRunner.createIndex(
      'chairs',
      new TableIndex({
        name: 'idx_chairs_room_active',
        columnNames: ['room_id', 'is_active'],
      }),
    );
    await queryRunner.createForeignKey(
      'chairs',
      new TableForeignKey({
        columnNames: ['room_id'],
        referencedTableName: 'rooms',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_chairs_room_id',
      }),
    );

    await queryRunner.addColumn(
      'employee_shifts',
      new TableColumn({
        name: 'chair_id',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.createForeignKey(
      'employee_shifts',
      new TableForeignKey({
        columnNames: ['chair_id'],
        referencedTableName: 'chairs',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employee_shifts_chair_id',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropForeignKey(
      'employee_shifts',
      'fk_employee_shifts_chair_id',
    );
    await queryRunner.dropColumn('employee_shifts', 'chair_id');
    await queryRunner.dropTable('chairs', true);
    await queryRunner.dropColumn('rooms', 'chairs_per_room');
    await queryRunner.dropColumn('rooms', 'beds_per_room');
    await queryRunner.dropColumn('rooms', 'configuration_type');
    await queryRunner.dropColumn('rooms', 'floor');
    await queryRunner.dropColumn('rooms', 'location_or_wing');
    await queryRunner.dropColumn('stations', 'custom_shift_times');
    await queryRunner.dropColumn('stations', 'default_chairs_per_room');
    await queryRunner.dropColumn('stations', 'default_beds_per_room');
    await queryRunner.dropColumn('stations', 'configuration_type');
    await queryRunner.dropColumn('stations', 'multi_station_noc');
    await queryRunner.dropColumn('stations', 'multi_station_pm');
    await queryRunner.dropColumn('stations', 'multi_station_am');
    await queryRunner.dropColumn('stations', 'required_mds');
    await queryRunner.dropColumn('stations', 'required_nps');
    await queryRunner.dropColumn('stations', 'required_treatment_nurses');
    await queryRunner.dropColumn('stations', 'required_sitters');
    await queryRunner.dropColumn('stations', 'required_cnas');
    await queryRunner.dropColumn('stations', 'required_charge_nurses');
    await queryRunner.dropColumn('stations', 'location');
    await queryRunner.dropColumn('departments', 'department_type');
    await queryRunner.dropColumn('departments', 'description');
  }
}
