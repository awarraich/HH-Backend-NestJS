import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Backfill referral status: set status = 'assigned' for referrals that already
 * have selected_organization_id set (so list filters and UI stay consistent).
 */
export class BackfillReferralStatusAssigned20260210000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `UPDATE referrals SET status = 'assigned' WHERE selected_organization_id IS NOT NULL AND status = 'pending'`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `UPDATE referrals SET status = 'pending' WHERE selected_organization_id IS NOT NULL AND status = 'assigned'`,
    );
  }
}
