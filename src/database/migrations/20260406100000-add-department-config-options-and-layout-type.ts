import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class AddDepartmentConfigOptionsAndLayoutType20260406100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Add layout_type to departments (IF NOT EXISTS)
    const deptTable = await queryRunner.getTable('departments');
    if (deptTable && !deptTable.findColumnByName('layout_type')) {
      await queryRunner.query(
        `ALTER TABLE "departments" ADD "layout_type" varchar(30) NULL`,
      );
    }

    // 2. Add room_type to rooms (IF NOT EXISTS)
    const roomsTable = await queryRunner.getTable('rooms');
    if (roomsTable && !roomsTable.findColumnByName('room_type')) {
      await queryRunner.query(
        `ALTER TABLE "rooms" ADD "room_type" varchar(50) NULL`,
      );
    }

    // 3. Create department_config_options table (IF NOT EXISTS)
    const configTableExists = await queryRunner.hasTable('department_config_options');
    if (!configTableExists) {
      await queryRunner.createTable(
        new Table({
          name: 'department_config_options',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'gen_random_uuid()',
            },
            { name: 'organization_id', type: 'uuid', isNullable: false },
            {
              name: 'category',
              type: 'varchar',
              length: '30',
              isNullable: false,
            },
            {
              name: 'value',
              type: 'varchar',
              length: '50',
              isNullable: false,
            },
            {
              name: 'label',
              type: 'varchar',
              length: '100',
              isNullable: false,
            },
            { name: 'description', type: 'text', isNullable: true },
            {
              name: 'icon',
              type: 'varchar',
              length: '50',
              isNullable: true,
            },
            {
              name: 'is_default',
              type: 'boolean',
              default: false,
              isNullable: false,
            },
            {
              name: 'is_active',
              type: 'boolean',
              default: true,
              isNullable: false,
            },
            { name: 'sort_order', type: 'smallint', isNullable: true },
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
        'department_config_options',
        new TableIndex({
          name: 'idx_dept_config_org_id',
          columnNames: ['organization_id'],
        }),
      );
      await queryRunner.createIndex(
        'department_config_options',
        new TableIndex({
          name: 'idx_dept_config_org_category',
          columnNames: ['organization_id', 'category'],
        }),
      );
      await queryRunner.createIndex(
        'department_config_options',
        new TableIndex({
          name: 'idx_dept_config_org_category_active',
          columnNames: ['organization_id', 'category', 'is_active'],
        }),
      );
      await queryRunner.createForeignKey(
        'department_config_options',
        new TableForeignKey({
          columnNames: ['organization_id'],
          referencedTableName: 'organizations',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_dept_config_options_org_id',
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const configTableExists = await queryRunner.hasTable('department_config_options');
    if (configTableExists) {
      await queryRunner.dropForeignKey(
        'department_config_options',
        'fk_dept_config_options_org_id',
      );
      await queryRunner.dropTable('department_config_options', true);
    }

    const roomsTable = await queryRunner.getTable('rooms');
    if (roomsTable?.findColumnByName('room_type')) {
      await queryRunner.dropColumn('rooms', 'room_type');
    }

    const deptTable = await queryRunner.getTable('departments');
    if (deptTable?.findColumnByName('layout_type')) {
      await queryRunner.dropColumn('departments', 'layout_type');
    }
  }
}
