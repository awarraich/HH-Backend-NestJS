import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Add fax and cover_images (banner carousel, 2–3 images) to company profile.
 */
export class AddFaxCoverImagesToCompanyProfile20260318000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "organization_company_profiles"
      ADD COLUMN IF NOT EXISTS "fax" varchar(50) NULL
    `);
    await queryRunner.query(`
      ALTER TABLE "organization_company_profiles"
      ADD COLUMN IF NOT EXISTS "cover_images" jsonb NOT NULL DEFAULT '[]'::jsonb
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "organization_company_profiles"
      DROP COLUMN IF EXISTS "cover_images"
    `);
    await queryRunner.query(`
      ALTER TABLE "organization_company_profiles"
      DROP COLUMN IF EXISTS "fax"
    `);
  }
}
