import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddStructuredAddressToCompanyProfile20260326000000
  implements MigrationInterface
{
  name = 'AddStructuredAddressToCompanyProfile20260326000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE organization_company_profiles
        ADD COLUMN IF NOT EXISTS address_line_1 VARCHAR(255),
        ADD COLUMN IF NOT EXISTS address_line_2 VARCHAR(255),
        ADD COLUMN IF NOT EXISTS city           VARCHAR(100),
        ADD COLUMN IF NOT EXISTS state          VARCHAR(100),
        ADD COLUMN IF NOT EXISTS zip_code       VARCHAR(20),
        ADD COLUMN IF NOT EXISTS country        VARCHAR(100)
    `);
    await queryRunner.query(`
      ALTER TABLE organization_company_profiles
        DROP COLUMN IF EXISTS address
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE organization_company_profiles
        ADD COLUMN IF NOT EXISTS address VARCHAR(500)
    `);
    await queryRunner.query(`
      ALTER TABLE organization_company_profiles
        DROP COLUMN IF EXISTS address_line_1,
        DROP COLUMN IF EXISTS address_line_2,
        DROP COLUMN IF EXISTS city,
        DROP COLUMN IF EXISTS state,
        DROP COLUMN IF EXISTS zip_code,
        DROP COLUMN IF EXISTS country
    `);
  }
}
