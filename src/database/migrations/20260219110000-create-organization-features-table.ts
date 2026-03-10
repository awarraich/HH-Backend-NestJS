import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

const FEATURES = [
  { code: 'operations_compliance', name: 'Company Documents & Compliance' },
  { code: 'operations_referral_management', name: 'Referral Management' },
  { code: 'operations_scheduling', name: 'Employee Scheduling' },
  { code: 'operations_job_management', name: 'Job Management & HR' },
  { code: 'patient_management_view_patients', name: 'Patient Management' },
  { code: 'operations_remote_monitoring', name: 'Remote Patient Monitoring' },
  { code: 'organization_setup', name: 'Organization Setup' },
  { code: 'operations_survey_audit', name: 'Survey & Audit' },
  { code: 'operations_calendar', name: 'Unified Calendar & Tasks' },
];

export class CreateOrganizationFeaturesTable20260219110000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'organization_features',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'code', type: 'varchar', length: '100', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: true },
          { name: 'description', type: 'text', isNullable: true },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    await queryRunner.createIndex(
      'organization_features',
      new TableIndex({
        name: 'idx_organization_features_code',
        columnNames: ['code'],
        isUnique: true,
      }),
    );

    for (const { code, name } of FEATURES) {
      await queryRunner.query(
        `INSERT INTO organization_features (id, code, name)
         SELECT gen_random_uuid(), $1::varchar, $2::varchar
         WHERE NOT EXISTS (SELECT 1 FROM organization_features WHERE code = $3::varchar)`,
        [code, name, code],
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('organization_features', true);
  }
}
