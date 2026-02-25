import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableUnique,
} from 'typeorm';

export class CreateProviderRolesTable20260224100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'provider_roles',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'code', type: 'varchar', length: '50', isNullable: false },
          { name: 'name', type: 'varchar', length: '100', isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP', isNullable: false },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'provider_roles',
      new TableUnique({ name: 'uq_provider_roles_code', columnNames: ['code'] }),
    );

    await queryRunner.createIndex(
      'provider_roles',
      new TableIndex({ name: 'idx_provider_roles_code', columnNames: ['code'] }),
    );

    await queryRunner.query(`
      INSERT INTO provider_roles (id, code, name, description)
      SELECT gen_random_uuid(), 'Sitter', 'Sitter', 'Sitter provider role'
      WHERE NOT EXISTS (SELECT 1 FROM provider_roles WHERE code = 'Sitter');
      INSERT INTO provider_roles (id, code, name, description)
      SELECT gen_random_uuid(), 'RC', 'RC', 'RC provider role'
      WHERE NOT EXISTS (SELECT 1 FROM provider_roles WHERE code = 'RC');
      INSERT INTO provider_roles (id, code, name, description)
      SELECT gen_random_uuid(), 'LN', 'LN', 'LN provider role'
      WHERE NOT EXISTS (SELECT 1 FROM provider_roles WHERE code = 'LN');
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('provider_roles', true);
  }
}
