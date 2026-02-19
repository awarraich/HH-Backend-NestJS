import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Ensures users.email has no NULLs so TypeORM sync can use NOT NULL.
 * - Adds email column as nullable if missing (e.g. old schema).
 * - Backfills NULL emails with a unique placeholder (e.g. OAuth-only users).
 * - Sets NOT NULL on users.email.
 */
export class BackfillUsersEmailNotNull20260219000001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add column if it does not exist (nullable)
    await queryRunner.query(`
      ALTER TABLE "users"
      ADD COLUMN IF NOT EXISTS "email" character varying(254)
    `);

    // Backfill NULL emails with a unique placeholder so NOT NULL is valid
    await queryRunner.query(`
      UPDATE "users"
      SET "email" = "id"::text || '@placeholder.local'
      WHERE "email" IS NULL
    `);

    // Now safe to set NOT NULL
    await queryRunner.query(`
      ALTER TABLE "users"
      ALTER COLUMN "email" SET NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "users"
      ALTER COLUMN "email" DROP NOT NULL
    `);
  }
}
