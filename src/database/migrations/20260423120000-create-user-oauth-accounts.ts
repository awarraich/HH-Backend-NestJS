import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateUserOAuthAccounts20260423120000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'user_oauth_accounts',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'user_id', type: 'uuid', isNullable: false },
          { name: 'provider', type: 'varchar', length: '32', isNullable: false },
          {
            name: 'provider_account_id',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          { name: 'access_token', type: 'text', isNullable: true },
          { name: 'refresh_token', type: 'text', isNullable: true },
          { name: 'scope', type: 'text', isNullable: true },
          {
            name: 'access_token_expires_at',
            type: 'timestamp with time zone',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'CURRENT_TIMESTAMP',
          },
        ],
        uniques: [
          {
            name: 'uq_user_oauth_accounts_user_provider',
            columnNames: ['user_id', 'provider'],
          },
        ],
        indices: [
          {
            name: 'idx_user_oauth_accounts_user_id',
            columnNames: ['user_id'],
          },
        ],
        foreignKeys: [
          {
            name: 'fk_user_oauth_accounts_user',
            columnNames: ['user_id'],
            referencedTableName: 'users',
            referencedColumnNames: ['id'],
            onDelete: 'CASCADE',
          },
        ],
      }),
      true,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('user_oauth_accounts');
  }
}
