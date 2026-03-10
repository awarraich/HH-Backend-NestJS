import { MigrationInterface, QueryRunner, TableColumn, TableForeignKey, TableIndex } from 'typeorm';

export class AlterEmployeesAndProfiles20260224100001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const employeesFk = await queryRunner.query(`
      SELECT tc.constraint_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
      WHERE tc.table_name = 'employees' AND tc.constraint_type = 'FOREIGN KEY'
        AND kcu.column_name = 'organization_id';
    `);
    const fkName =
      Array.isArray(employeesFk) && employeesFk[0]
        ? (employeesFk[0] as { constraint_name: string }).constraint_name
        : 'fk_employees_organization_id';
    try {
      await queryRunner.dropForeignKey('employees', fkName);
    } catch {
      // FK may have different name from TypeORM
      const alt = await queryRunner.query(`
        SELECT constraint_name FROM information_schema.table_constraints
        WHERE table_name = 'employees' AND constraint_type = 'FOREIGN KEY'
          AND constraint_name LIKE '%organization%';
      `);
      if (Array.isArray(alt) && alt[0]) {
        await queryRunner.dropForeignKey(
          'employees',
          (alt[0] as { constraint_name: string }).constraint_name,
        );
      }
    }

    await queryRunner.changeColumn(
      'employees',
      'organization_id',
      new TableColumn({ name: 'organization_id', type: 'uuid', isNullable: true }),
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

    await queryRunner.addColumn(
      'employees',
      new TableColumn({ name: 'employment_type', type: 'varchar', length: '20', isNullable: true }),
    );
    await queryRunner.addColumn(
      'employees',
      new TableColumn({ name: 'notes', type: 'text', isNullable: true }),
    );
    await queryRunner.addColumn(
      'employees',
      new TableColumn({ name: 'provider_role_id', type: 'uuid', isNullable: true }),
    );

    await queryRunner.createForeignKey(
      'employees',
      new TableForeignKey({
        columnNames: ['provider_role_id'],
        referencedTableName: 'provider_roles',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_employees_provider_role_id',
      }),
    );

    await queryRunner.createIndex(
      'employees',
      new TableIndex({ name: 'idx_employees_provider_role_id', columnNames: ['provider_role_id'] }),
    );
    await queryRunner.createIndex(
      'employees',
      new TableIndex({ name: 'idx_employees_employment_type', columnNames: ['employment_type'] }),
    );

    await queryRunner.query(`
      CREATE UNIQUE INDEX uq_employees_user_id_null_org ON employees (user_id) WHERE organization_id IS NULL;
    `);

    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({ name: 'date_of_birth', type: 'date', isNullable: true }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({ name: 'specialization', type: 'varchar', length: '100', isNullable: true }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({ name: 'years_of_experience', type: 'integer', isNullable: true }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({ name: 'certification', type: 'varchar', length: '100', isNullable: true }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({ name: 'board_certifications', type: 'jsonb', isNullable: true }),
    );

    await queryRunner.query(`
      INSERT INTO roles (id, name, description)
      SELECT (SELECT COALESCE(MAX(id), 0) + 1 FROM roles), 'EMPLOYEE', 'Employee'
      WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'EMPLOYEE');
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS uq_employees_user_id_null_org;`);
    await queryRunner.dropIndex('employees', 'idx_employees_employment_type');
    await queryRunner.dropIndex('employees', 'idx_employees_provider_role_id');
    await queryRunner.dropForeignKey('employees', 'fk_employees_provider_role_id');
    await queryRunner.dropColumn('employees', 'provider_role_id');
    await queryRunner.dropColumn('employees', 'notes');
    await queryRunner.dropColumn('employees', 'employment_type');

    await queryRunner.dropForeignKey('employees', 'fk_employees_organization_id');
    await queryRunner.changeColumn(
      'employees',
      'organization_id',
      new TableColumn({ name: 'organization_id', type: 'uuid', isNullable: false }),
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

    await queryRunner.dropColumn('employee_profiles', 'board_certifications');
    await queryRunner.dropColumn('employee_profiles', 'certification');
    await queryRunner.dropColumn('employee_profiles', 'years_of_experience');
    await queryRunner.dropColumn('employee_profiles', 'specialization');
    await queryRunner.dropColumn('employee_profiles', 'date_of_birth');

    await queryRunner.query(`DELETE FROM roles WHERE name = 'EMPLOYEE'`);
  }
}
