import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
} from 'typeorm';

/**
 * Initial migration: creates the users table.
 * Required because AddGoogleIdToUsers (20260128060000) and later migrations
 * assume this table exists. Use this for fresh databases that never had
 * schema sync or a previous create-users migration.
 */
export class CreateUsersTable20260101000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('users');
    if (table) {
      return; // Table already exists (e.g. from sync or previous setup)
    }

    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'uuid_generate_v4()',
          },
          {
            name: 'firstName',
            type: 'varchar',
            length: '255',
            isNullable: false,
          },
          {
            name: 'lastName',
            type: 'varchar',
            length: '255',
            isNullable: false,
          },
          {
            name: 'email',
            type: 'varchar',
            length: '254',
            isNullable: false,
          },
          {
            name: 'password',
            type: 'varchar',
            length: '128',
            isNullable: false,
          },
          {
            name: 'is_active',
            type: 'boolean',
            default: true,
          },
          {
            name: 'email_verified',
            type: 'boolean',
            default: false,
          },
          {
            name: 'email_verification_token',
            type: 'varchar',
            length: '100',
            isNullable: true,
          },
          {
            name: 'email_verification_sent_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'password_reset_token',
            type: 'varchar',
            length: '100',
            isNullable: true,
          },
          {
            name: 'password_reset_sent_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'is_two_fa_enabled',
            type: 'boolean',
            default: false,
          },
          {
            name: 'totp_secret',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'totp_secret_created_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'last_2fa_verified_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'last_login',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );

    await queryRunner.createIndex(
      'users',
      new TableIndex({
        name: 'UQ_users_email',
        columnNames: ['email'],
        isUnique: true,
      }),
    );
    await queryRunner.createIndex(
      'users',
      new TableIndex({
        name: 'IDX_users_email_verification_token',
        columnNames: ['email_verification_token'],
      }),
    );
    await queryRunner.createIndex(
      'users',
      new TableIndex({
        name: 'IDX_users_password_reset_token',
        columnNames: ['password_reset_token'],
      }),
    );
    await queryRunner.createIndex(
      'users',
      new TableIndex({
        name: 'IDX_users_is_active',
        columnNames: ['is_active'],
      }),
    );
    await queryRunner.createIndex(
      'users',
      new TableIndex({
        name: 'IDX_users_email_verified',
        columnNames: ['email_verified'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('users', true);
  }
}
