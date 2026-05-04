import { MigrationInterface, QueryRunner, Table, TableForeignKey } from 'typeorm';

export class CreateOrganizationIntegrations20260501200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'organization_integrations',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'org_id', type: 'uuid', isNullable: false },
          { name: 'provider', type: 'varchar', length: '32', isNullable: false },
          { name: 'status', type: 'varchar', length: '16', isNullable: false, default: "'pending'" },
          { name: 'workspace_domain', type: 'varchar', length: '255', isNullable: true },
          { name: 'config', type: 'jsonb', isNullable: true },
          { name: 'enabled_by_user_id', type: 'uuid', isNullable: true },
          { name: 'enabled_at', type: 'timestamp with time zone', isNullable: true },
          { name: 'verified_at', type: 'timestamp with time zone', isNullable: true },
          { name: 'disabled_at', type: 'timestamp with time zone', isNullable: true },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
        ],
        uniques: [
          {
            name: 'uq_organization_integrations_org_provider',
            columnNames: ['org_id', 'provider'],
          },
        ],
        checks: [
          {
            name: 'organization_integrations_status_values',
            expression: "status IN ('pending', 'active', 'disabled')",
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'organization_integrations',
      new TableForeignKey({
        name: 'fk_organization_integrations_org',
        columnNames: ['org_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createForeignKey(
      'organization_integrations',
      new TableForeignKey({
        name: 'fk_organization_integrations_enabled_by',
        columnNames: ['enabled_by_user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
      }),
    );

    await queryRunner.query(
      `CREATE INDEX idx_organization_integrations_org_id ON organization_integrations (org_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_organization_integrations_status ON organization_integrations (status)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS idx_organization_integrations_status');
    await queryRunner.query('DROP INDEX IF EXISTS idx_organization_integrations_org_id');
    await queryRunner.dropTable('organization_integrations');
  }
}
