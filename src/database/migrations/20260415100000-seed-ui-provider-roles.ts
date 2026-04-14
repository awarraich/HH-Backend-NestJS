import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Seed the UI-facing staff role options into `provider_roles` so the Add
 * Department dropdown can load them dynamically. Idempotent: each row uses
 * `WHERE NOT EXISTS (SELECT 1 FROM provider_roles WHERE code = ?)`.
 *
 * Skips codes already seeded by earlier migrations (RN, LVN, PT, PTA, OT,
 * COTA, ST, MSW, HHA, MD, IDPCS, Sitter, RC, LN) and intentionally omits
 * "OTHER" — it is a UI sentinel paired with a free-text custom name, not a
 * real role.
 */
export class SeedUiProviderRoles20260415100000 implements MigrationInterface {
  private readonly roles: Array<{ code: string; name: string; description: string }> = [
    { code: 'ADMINISTRATOR', name: 'Administrator', description: 'Administrator' },
    { code: 'ASST_ADMINISTRATOR', name: 'Assistant Administrator', description: 'Assistant Administrator' },
    { code: 'ASST_CHIEF', name: 'Assistant Chief', description: 'Assistant Chief' },
    { code: 'BEREAVEMENT_COORD', name: 'Bereavement Coordinator', description: 'Bereavement Coordinator' },
    { code: 'BIZ_DEV', name: 'Business Development', description: 'Business Development' },
    { code: 'CAREGIVER', name: 'Caregiver', description: 'Caregiver' },
    { code: 'CHAPLAIN', name: 'Chaplain', description: 'Chaplain' },
    { code: 'CHIEF', name: 'Chief', description: 'Chief' },
    { code: 'CLINICAL_SUPERVISOR', name: 'Clinical Supervisor', description: 'Clinical Supervisor' },
    { code: 'CNA', name: 'CNA - Certified Nursing Assistant', description: 'Certified Nursing Assistant' },
    { code: 'DPCS', name: 'Director of Patient Care (DPCS)', description: 'Director of Patient Care Services' },
    { code: 'DRIVER', name: 'Driver', description: 'Driver' },
    { code: 'HELPER', name: 'Helper', description: 'Helper' },
    { code: 'MAINTENANCE', name: 'Maintenance', description: 'Maintenance' },
    { code: 'MANAGER', name: 'Manager', description: 'Manager' },
    { code: 'MARKETER', name: 'Marketer', description: 'Marketer' },
    { code: 'MA', name: 'MA', description: 'Medical Assistant' },
    { code: 'NP', name: 'NP - Nurse Practitioner', description: 'Nurse Practitioner' },
    { code: 'OTA', name: 'OTA - Occupational Therapy Assistant', description: 'Occupational Therapy Assistant' },
    { code: 'PA', name: 'PA - Physician Assistant', description: 'Physician Assistant' },
    { code: 'PHARMACIST', name: 'Pharmacist', description: 'Pharmacist' },
    { code: 'PHARMACY_TECH', name: 'Pharmacy Technician', description: 'Pharmacy Technician' },
    { code: 'PHARMACY_CLERK', name: 'Pharmacy Clerk', description: 'Pharmacy Clerk' },
    { code: 'LAB_TECH', name: 'Lab Technician', description: 'Lab Technician' },
    { code: 'DISPATCHER', name: 'Dispatcher', description: 'Dispatcher' },
    { code: 'ATTENDANT', name: 'Attendant', description: 'Attendant' },
    { code: 'RECEPTIONIST', name: 'Receptionist', description: 'Receptionist' },
    { code: 'SECURITY', name: 'Security Guard', description: 'Security Guard' },
    { code: 'SPECIALIST', name: 'Specialist', description: 'Specialist' },
    { code: 'TREATMENT_NURSE', name: 'Treatment Nurse', description: 'Treatment Nurse' },
    { code: 'VOLUNTEER', name: 'Volunteer', description: 'Volunteer' },
  ];

  public async up(queryRunner: QueryRunner): Promise<void> {
    for (const role of this.roles) {
      await queryRunner.query(
        `INSERT INTO provider_roles (id, code, name, description)
         SELECT gen_random_uuid(), $1::varchar, $2, $3
         WHERE NOT EXISTS (SELECT 1 FROM provider_roles WHERE code = $1::varchar)`,
        [role.code, role.name, role.description],
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const codes = this.roles.map((r) => r.code);
    await queryRunner.query(
      `DELETE FROM provider_roles WHERE code = ANY($1::varchar[])`,
      [codes],
    );
  }
}
