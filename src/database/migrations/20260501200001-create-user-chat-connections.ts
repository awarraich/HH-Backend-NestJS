import { MigrationInterface, QueryRunner, Table, TableForeignKey } from 'typeorm';

export class CreateUserChatConnections20260501200001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'user_chat_connections',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'org_id', type: 'uuid', isNullable: false },
          { name: 'provider', type: 'varchar', length: '32', isNullable: false },
          { name: 'chat_user_id', type: 'varchar', length: '255', isNullable: true },
          { name: 'dm_space_name', type: 'varchar', length: '255', isNullable: true },
          { name: 'status', type: 'varchar', length: '16', isNullable: false, default: "'pending'" },
          { name: 'chat_eligible', type: 'boolean', isNullable: false, default: true },
          { name: 'connected_at', type: 'timestamp with time zone', isNullable: true },
          { name: 'revoked_at', type: 'timestamp with time zone', isNullable: true },
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
            name: 'uq_user_chat_connections_user_provider',
            columnNames: ['user_id', 'provider'],
          },
        ],
        checks: [
          {
            name: 'user_chat_connections_status_values',
            expression: "status IN ('pending', 'connected', 'revoked')",
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'user_chat_connections',
      new TableForeignKey({
        name: 'fk_user_chat_connections_user',
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createForeignKey(
      'user_chat_connections',
      new TableForeignKey({
        name: 'fk_user_chat_connections_org',
        columnNames: ['org_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.query(
      `CREATE INDEX idx_user_chat_connections_user_id ON user_chat_connections (user_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_user_chat_connections_org_id ON user_chat_connections (org_id)`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_user_chat_connections_status ON user_chat_connections (status)`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS idx_user_chat_connections_status');
    await queryRunner.query('DROP INDEX IF EXISTS idx_user_chat_connections_org_id');
    await queryRunner.query('DROP INDEX IF EXISTS idx_user_chat_connections_user_id');
    await queryRunner.dropTable('user_chat_connections');
  }
}
