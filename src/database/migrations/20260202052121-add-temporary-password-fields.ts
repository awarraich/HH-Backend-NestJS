import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddTemporaryPasswordFields20260202052121 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'temporary_password',
        type: 'varchar',
        length: '128',
        isNullable: true,
      }),
    );

    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'temporary_password_expires_at',
        type: 'timestamp',
        isNullable: true,
      }),
    );

    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'must_change_password',
        type: 'boolean',
        default: false,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('users', 'must_change_password');
    await queryRunner.dropColumn('users', 'temporary_password_expires_at');
    await queryRunner.dropColumn('users', 'temporary_password');
  }
}

