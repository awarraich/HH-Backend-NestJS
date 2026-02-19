import { MigrationInterface, QueryRunner } from 'typeorm';

export class PatientsNullableUserIdAndOrganization20260209000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const patientsTable = await queryRunner.getTable('patients');
    if (!patientsTable) {
      return;
    }

    // Use raw SQL to avoid TypeORM's changeColumn re-dropping the constraint internally
    await queryRunner.query(
      `ALTER TABLE "patients" DROP CONSTRAINT IF EXISTS "patients_user_id_key"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "patients_user_id_key"`,
    );
    await queryRunner.query(
      `ALTER TABLE "patients" ALTER COLUMN "user_id" DROP NOT NULL`,
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "idx_patients_user_id_unique" ON "patients" ("user_id") WHERE "user_id" IS NOT NULL`,
    );

    await queryRunner.query(
      `ALTER TABLE "patients" ADD COLUMN IF NOT EXISTS "organization_id" uuid`,
    );
    await queryRunner.query(
      `ALTER TABLE "patients" ADD CONSTRAINT "fk_patients_organization_id" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "patients" DROP CONSTRAINT IF EXISTS "fk_patients_organization_id"`,
    );
    await queryRunner.query(
      `ALTER TABLE "patients" DROP COLUMN IF EXISTS "organization_id"`,
    );
    await queryRunner.query(
      `DROP INDEX IF EXISTS "idx_patients_user_id_unique"`,
    );
    await queryRunner.query(
      `ALTER TABLE "patients" ALTER COLUMN "user_id" SET NOT NULL`,
    );
    await queryRunner.query(
      `ALTER TABLE "patients" ADD CONSTRAINT "patients_user_id_key" UNIQUE ("user_id")`,
    );
  }
}
