import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Add four nullable onboarding-completion timestamps to `employee_profiles`.
 *
 *   - `portal_wizard_completed_at`         — set once when the first-login
 *     wizard is finished (or skipped). Authoritative replacement for the
 *     localStorage flag the frontend used to rely on; survives device
 *     swaps and lets HR pull "who hasn't completed setup" reports.
 *   - `hipaa_acknowledged_at`              — caregiver's HIPAA / PHI-handling
 *     acknowledgement. Captured for compliance audits.
 *   - `background_check_acknowledged_at`   — consent to the background check
 *     that home-health roles require before scheduling visits.
 *   - `i9_acknowledged_at`                 — federal Form I-9 acknowledgement
 *     (employee understands they must complete I-9 with HR within 3 days).
 *
 * All four are nullable because existing employees (pre-rollout) won't have
 * acknowledged anything; the wizard re-prompts when any of them is null.
 * No backfill is needed — null = "never acknowledged".
 */
export class AddOnboardingTimestampsToEmployeeProfiles20260429100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({
        name: 'portal_wizard_completed_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({
        name: 'hipaa_acknowledged_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({
        name: 'background_check_acknowledged_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({
        name: 'i9_acknowledged_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn(
      'employee_profiles',
      'i9_acknowledged_at',
    );
    await queryRunner.dropColumn(
      'employee_profiles',
      'background_check_acknowledged_at',
    );
    await queryRunner.dropColumn(
      'employee_profiles',
      'hipaa_acknowledged_at',
    );
    await queryRunner.dropColumn(
      'employee_profiles',
      'portal_wizard_completed_at',
    );
  }
}
