import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateEmployeesTable20260219200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'employees',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'role', type: 'varchar', length: '20', isNullable: true },
          { name: 'status', type: 'varchar', length: '20', default: "'active'", isNullable: false },
          { name: 'start_date', type: 'date', isNullable: true },
          { name: 'end_date', type: 'date', isNullable: true },
          { name: 'department', type: 'varchar', length: '100', isNullable: true },
          { name: 'position_title', type: 'varchar', length: '100', isNullable: true },
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

    await queryRunner.createUniqueConstraint(
      'employees',
      new TableUnique({
        name: 'uq_employees_user_id_organization_id',
        columnNames: ['user_id', 'organization_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'employees',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employees_user_id',
      }),
    );

    await queryRunner.createForeignKey(
      'employees',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employees_organization_id',
      }),
    );

    await queryRunner.createIndex(
      'employees',
      new TableIndex({ name: 'idx_employees_user_id', columnNames: ['user_id'] }),
    );
    await queryRunner.createIndex(
      'employees',
      new TableIndex({ name: 'idx_employees_organization_id', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'employees',
      new TableIndex({ name: 'idx_employees_status', columnNames: ['status'] }),
    );
    await queryRunner.createIndex(
      'employees',
      new TableIndex({
        name: 'idx_employees_organization_id_status',
        columnNames: ['organization_id', 'status'],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'employee_profiles',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: false },
          { name: 'profile_image', type: 'varchar', length: '100', isNullable: true },
          { name: 'address', type: 'text', isNullable: true },
          { name: 'phone_number', type: 'varchar', length: '20', isNullable: true },
          { name: 'gender', type: 'varchar', length: '20', isNullable: true },
          { name: 'age', type: 'integer', isNullable: true },
          { name: 'emergency_contact', type: 'jsonb', isNullable: true },
          {
            name: 'onboarding_status',
            type: 'varchar',
            length: '10',
            default: "'pending'",
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

    await queryRunner.createUniqueConstraint(
      'employee_profiles',
      new TableUnique({
        name: 'uq_employee_profiles_employee_id',
        columnNames: ['employee_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'employee_profiles',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_profiles_employee_id',
      }),
    );

    await queryRunner.createIndex(
      'employee_profiles',
      new TableIndex({
        name: 'idx_employee_profiles_employee_id',
        columnNames: ['employee_id'],
        isUnique: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('employee_profiles', 'idx_employee_profiles_employee_id');
    await queryRunner.dropForeignKey('employee_profiles', 'fk_employee_profiles_employee_id');
    await queryRunner.dropTable('employee_profiles', true);

    await queryRunner.dropIndex('employees', 'idx_employees_organization_id_status');
    await queryRunner.dropIndex('employees', 'idx_employees_status');
    await queryRunner.dropIndex('employees', 'idx_employees_organization_id');
    await queryRunner.dropIndex('employees', 'idx_employees_user_id');
    await queryRunner.dropForeignKey('employees', 'fk_employees_organization_id');
    await queryRunner.dropForeignKey('employees', 'fk_employees_user_id');
    await queryRunner.dropTable('employees', true);
  }
}
