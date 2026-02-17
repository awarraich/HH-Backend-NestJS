import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Allow NULL password for OAuth-only users (e.g. Google sign-in).
 * Email/password users continue to have a hashed password; OAuth users have password = NULL.
 */
export class MakeUsersPasswordNullable20260217000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" ALTER COLUMN "password" DROP NOT NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" ALTER COLUMN "password" SET NOT NULL`,
    );
  }
}
