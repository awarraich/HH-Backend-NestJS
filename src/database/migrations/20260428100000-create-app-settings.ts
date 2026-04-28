import { MigrationInterface, QueryRunner, Table, TableForeignKey } from 'typeorm';

/**
 * Generic key/value settings for the application. Two scopes:
 *   - global: one row per key, organization_id IS NULL
 *   - organization: one row per (key, organization_id)
 *
 * Resolution order at read-time is per-org → global → env-var fallback.
 * Postgres treats NULL as distinct in unique constraints, so we use two
 * partial unique indexes (one for global, one for per-org) instead of a
 * single composite unique to enforce the "one row per scope" invariant.
 */
export class CreateAppSettings20260428100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'app_settings',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'key', type: 'varchar', length: '100', isNullable: false },
          { name: 'scope', type: 'varchar', length: '20', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: true },
          { name: 'value', type: 'jsonb', isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'updated_by', type: 'uuid', isNullable: true },
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
        checks: [
          {
            name: 'app_settings_scope_consistent',
            expression:
              "(scope = 'global' AND organization_id IS NULL) OR (scope = 'organization' AND organization_id IS NOT NULL)",
          },
          {
            name: 'app_settings_scope_values',
            expression: "scope IN ('global', 'organization')",
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'app_settings',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.query(
      `CREATE UNIQUE INDEX app_settings_global_key_unique
         ON app_settings (key)
         WHERE organization_id IS NULL`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX app_settings_org_key_unique
         ON app_settings (organization_id, key)
         WHERE organization_id IS NOT NULL`,
    );
    await queryRunner.query(
      `CREATE INDEX app_settings_key_idx ON app_settings (key)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS app_settings_key_idx');
    await queryRunner.query('DROP INDEX IF EXISTS app_settings_org_key_unique');
    await queryRunner.query('DROP INDEX IF EXISTS app_settings_global_key_unique');
    await queryRunner.dropTable('app_settings');
  }
}
