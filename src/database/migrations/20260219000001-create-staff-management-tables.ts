import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateStaffManagementTables20260219000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'staff_roles',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'name', type: 'varchar', length: '50', isUnique: true, isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createIndex(
      'staff_roles',
      new TableIndex({ name: 'idx_staff_roles_name', columnNames: ['name'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'organization_staff',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'staff_role_id', type: 'uuid', isNullable: false },
          { name: 'status', type: 'varchar', length: '20', default: "'ACTIVE'", isNullable: false },
          { name: 'start_date', type: 'date', isNullable: true },
          { name: 'end_date', type: 'date', isNullable: true },
          { name: 'department', type: 'varchar', length: '100', isNullable: true },
          { name: 'position_title', type: 'varchar', length: '100', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'created_by', type: 'uuid', isNullable: true },
          { name: 'updated_by', type: 'uuid', isNullable: true },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'organization_staff',
      new TableUnique({
        name: 'uq_organization_staff_org_user_role',
        columnNames: ['organization_id', 'user_id', 'staff_role_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'organization_staff',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_organization_staff_organization_id',
      }),
    );

    await queryRunner.createForeignKey(
      'organization_staff',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_organization_staff_user_id',
      }),
    );

    await queryRunner.createForeignKey(
      'organization_staff',
      new TableForeignKey({
        columnNames: ['staff_role_id'],
        referencedTableName: 'staff_roles',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
        name: 'fk_organization_staff_staff_role_id',
      }),
    );

    await queryRunner.createIndex(
      'organization_staff',
      new TableIndex({ name: 'idx_organization_staff_organization_id', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'organization_staff',
      new TableIndex({ name: 'idx_organization_staff_user_id', columnNames: ['user_id'] }),
    );
    await queryRunner.createIndex(
      'organization_staff',
      new TableIndex({ name: 'idx_organization_staff_staff_role_id', columnNames: ['staff_role_id'] }),
    );
    await queryRunner.createIndex(
      'organization_staff',
      new TableIndex({ name: 'idx_organization_staff_org_status', columnNames: ['organization_id', 'status'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'organization_staff_role_permissions',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'staff_role_id', type: 'uuid', isNullable: false },
          { name: 'feature', type: 'varchar', length: '100', isNullable: false },
          { name: 'has_access', type: 'boolean', default: false, isNullable: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
          { name: 'updated_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'organization_staff_role_permissions',
      new TableUnique({
        name: 'uq_org_staff_role_permissions_org_role_feature',
        columnNames: ['organization_id', 'staff_role_id', 'feature'],
      }),
    );

    await queryRunner.createForeignKey(
      'organization_staff_role_permissions',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_org_staff_role_permissions_organization_id',
      }),
    );

    await queryRunner.createForeignKey(
      'organization_staff_role_permissions',
      new TableForeignKey({
        columnNames: ['staff_role_id'],
        referencedTableName: 'staff_roles',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_org_staff_role_permissions_staff_role_id',
      }),
    );

    await queryRunner.createIndex(
      'organization_staff_role_permissions',
      new TableIndex({ name: 'idx_org_staff_role_permissions_organization_id', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'organization_staff_role_permissions',
      new TableIndex({ name: 'idx_org_staff_role_permissions_staff_role_id', columnNames: ['staff_role_id'] }),
    );
    await queryRunner.createIndex(
      'organization_staff_role_permissions',
      new TableIndex({ name: 'idx_org_staff_role_permissions_feature', columnNames: ['feature'] }),
    );

    await queryRunner.query(`
      INSERT INTO staff_roles (id, name, description)
      SELECT gen_random_uuid(), 'HR', 'Human Resources' WHERE NOT EXISTS (SELECT 1 FROM staff_roles WHERE name = 'HR');
      INSERT INTO staff_roles (id, name, description)
      SELECT gen_random_uuid(), 'ASSISTANT_HR', 'Assistant Human Resources' WHERE NOT EXISTS (SELECT 1 FROM staff_roles WHERE name = 'ASSISTANT_HR');
      INSERT INTO staff_roles (id, name, description)
      SELECT gen_random_uuid(), 'MANAGER', 'Manager' WHERE NOT EXISTS (SELECT 1 FROM staff_roles WHERE name = 'MANAGER');
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('organization_staff_role_permissions', true);
    await queryRunner.dropTable('organization_staff', true);
    await queryRunner.dropTable('staff_roles', true);
  }
}
