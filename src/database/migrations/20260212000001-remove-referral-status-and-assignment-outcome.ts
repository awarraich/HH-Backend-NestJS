import { MigrationInterface, QueryRunner } from 'typeorm';

export class RemoveReferralStatusAndAssignmentOutcome20260212000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('referrals', 'idx_referrals_status');
    await queryRunner.dropColumn('referrals', 'status');

    await queryRunner.dropColumn('referral_organizations', 'assignment_outcome');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "referrals" ADD "status" varchar(20) NOT NULL DEFAULT 'pending'`,
    );
    await queryRunner.query(`CREATE INDEX "idx_referrals_status" ON "referrals" ("status")`);

    await queryRunner.query(
      `ALTER TABLE "referral_organizations" ADD "assignment_outcome" varchar(20)`,
    );
  }
}
