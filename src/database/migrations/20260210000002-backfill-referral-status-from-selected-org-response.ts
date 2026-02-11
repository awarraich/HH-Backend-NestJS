import { MigrationInterface, QueryRunner } from 'typeorm';

export class BackfillReferralStatusFromSelectedOrgResponse20260210000002
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      UPDATE referrals r
      SET status = ro.response_status
      FROM referral_organizations ro
      WHERE ro.referral_id = r.id
        AND ro.organization_id = r.selected_organization_id
        AND r.selected_organization_id IS NOT NULL
        AND ro.response_status IN ('accepted', 'declined', 'negotiation')
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      UPDATE referrals r
      SET status = 'assigned'
      FROM referral_organizations ro
      WHERE ro.referral_id = r.id
        AND ro.organization_id = r.selected_organization_id
        AND r.selected_organization_id IS NOT NULL
        AND r.status IN ('accepted', 'declined', 'negotiation')
    `);
  }
}
