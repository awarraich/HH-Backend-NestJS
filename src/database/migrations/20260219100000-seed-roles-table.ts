import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
} from 'typeorm';

/**
 * Creates the roles and user_roles tables (if they don't already exist from
 * TypeORM sync) and seeds the five application roles.
 *
 * The GET /v1/api/auth/roles/public endpoint relies on ORGANIZATION, PATIENT,
 * and EMPLOYEE rows existing in the roles table.
 */
export class SeedRolesTable20260219100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const rolesTable = await queryRunner.getTable('roles');
    if (!rolesTable) {
      await queryRunner.createTable(
        new Table({
          name: 'roles',
          columns: [
            {
              name: 'id',
              type: 'smallint',
              isPrimary: true,
            },
            {
              name: 'name',
              type: 'varchar',
              length: '50',
              isUnique: true,
            },
            {
              name: 'description',
              type: 'text',
              isNullable: true,
            },
            {
              name: 'created_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );

      await queryRunner.createIndex(
        'roles',
        new TableIndex({
          name: 'IDX_roles_name',
          columnNames: ['name'],
          isUnique: true,
        }),
      );
    }

    const userRolesTable = await queryRunner.getTable('user_roles');
    if (!userRolesTable) {
      await queryRunner.createTable(
        new Table({
          name: 'user_roles',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            {
              name: 'user_id',
              type: 'uuid',
            },
            {
              name: 'role_id',
              type: 'smallint',
            },
            {
              name: 'created_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
          uniques: [
            {
              name: 'UQ_user_roles_user_role',
              columnNames: ['user_id', 'role_id'],
            },
          ],
          foreignKeys: [
            {
              name: 'FK_user_roles_user',
              columnNames: ['user_id'],
              referencedTableName: 'users',
              referencedColumnNames: ['id'],
              onDelete: 'CASCADE',
            },
            {
              name: 'FK_user_roles_role',
              columnNames: ['role_id'],
              referencedTableName: 'roles',
              referencedColumnNames: ['id'],
              onDelete: 'CASCADE',
            },
          ],
        }),
        true,
      );

      await queryRunner.createIndex(
        'user_roles',
        new TableIndex({
          name: 'IDX_user_roles_user_id',
          columnNames: ['user_id'],
        }),
      );

      await queryRunner.createIndex(
        'user_roles',
        new TableIndex({
          name: 'IDX_user_roles_role_id',
          columnNames: ['role_id'],
        }),
      );
    }

    const roles = [
      { id: 1, name: 'ADMIN', description: 'System administrator' },
      { id: 2, name: 'ORGANIZATION', description: 'Healthcare organization account' },
      { id: 3, name: 'PATIENT', description: 'Patient account' },
      { id: 4, name: 'EMPLOYEE', description: 'Organization employee' },
      { id: 5, name: 'BLOGGER', description: 'Blog content author' },
    ];

    for (const role of roles) {
      const exists = await queryRunner.query(
        `SELECT 1 FROM roles WHERE id = $1 OR name = $2 LIMIT 1`,
        [role.id, role.name],
      );

      if (exists.length === 0) {
        await queryRunner.query(
          `INSERT INTO roles (id, name, description) VALUES ($1, $2, $3)`,
          [role.id, role.name, role.description],
        );
      }
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DELETE FROM roles WHERE name IN ('ADMIN', 'ORGANIZATION', 'PATIENT', 'EMPLOYEE', 'BLOGGER')`,
    );
  }
}
