import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Enforce unique company name across organizations (case-insensitive, trimmed).
 * One organization per company name. Partial index excludes null/empty names.
 */
export class UniqueCompanyNameCompanyProfile20260319000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE UNIQUE INDEX "idx_organization_company_profiles_company_name_unique"
      ON "organization_company_profiles" (
        TRIM(BOTH '-' FROM LOWER(TRIM(REGEXP_REPLACE(COALESCE("company_name", ''), '[^a-z0-9]+', '-', 'gi'))))
      )
      WHERE "company_name" IS NOT NULL AND TRIM("company_name") <> ''
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DROP INDEX IF EXISTS "idx_organization_company_profiles_company_name_unique"
    `);
  }
}
