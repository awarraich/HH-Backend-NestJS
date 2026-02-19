import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

/**
 * Creates organizations, patients, and patient_profiles tables required by
 * later migrations (PatientsNullableUserIdAndOrganization, CreateReferralTables).
 * Skips creation if each table already exists (e.g. from sync or existing DB).
 */
export class CreateOrganizationsPatientsTables20260208000000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // organization_types (referenced by referral tables)
    if (!(await queryRunner.getTable('organization_types'))) {
      await queryRunner.createTable(
        new Table({
          name: 'organization_types',
          columns: [
            { name: 'id', type: 'smallint', isPrimary: true },
            { name: 'name', type: 'varchar', length: '50', isNullable: false },
            {
              name: 'created_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );
      await queryRunner.createIndex(
        'organization_types',
        new TableIndex({
          name: 'IDX_organization_types_name',
          columnNames: ['name'],
          isUnique: true,
        }),
      );
    }

    // organizations
    if (!(await queryRunner.getTable('organizations'))) {
      await queryRunner.createTable(
        new Table({
          name: 'organizations',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            { name: 'user_id', type: 'uuid', isNullable: false },
            {
              name: 'organization_name',
              type: 'varchar',
              length: '255',
              isNullable: true,
            },
            { name: 'tax_id', type: 'varchar', length: '20', isNullable: true },
            {
              name: 'registration_number',
              type: 'varchar',
              length: '50',
              isNullable: true,
            },
            { name: 'website', type: 'varchar', length: '200', isNullable: true },
            { name: 'description', type: 'text', isNullable: true },
            {
              name: 'created_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
            {
              name: 'updated_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'organizations',
        new TableForeignKey({
          columnNames: ['user_id'],
          referencedTableName: 'users',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_organizations_user_id',
        }),
      );
      await queryRunner.createIndex(
        'organizations',
        new TableIndex({
          name: 'UQ_organizations_user_id',
          columnNames: ['user_id'],
          isUnique: true,
        }),
      );
      await queryRunner.createIndex(
        'organizations',
        new TableIndex({
          name: 'IDX_organizations_organization_name',
          columnNames: ['organization_name'],
        }),
      );
      await queryRunner.createIndex(
        'organizations',
        new TableIndex({
          name: 'IDX_organizations_tax_id',
          columnNames: ['tax_id'],
        }),
      );
    }

    // patients (before 20260209000001: user_id NOT NULL UNIQUE, no organization_id)
    if (!(await queryRunner.getTable('patients'))) {
      await queryRunner.createTable(
        new Table({
          name: 'patients',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            {
              name: 'user_id',
              type: 'uuid',
              isNullable: false,
            },
            {
              name: 'created_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
            {
              name: 'updated_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'patients',
        new TableForeignKey({
          columnNames: ['user_id'],
          referencedTableName: 'users',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_patients_user_id',
        }),
      );
      await queryRunner.createUniqueConstraint(
        'patients',
        new TableUnique({
          name: 'patients_user_id_key',
          columnNames: ['user_id'],
        }),
      );
      await queryRunner.createIndex(
        'patients',
        new TableIndex({
          name: 'IDX_patients_user_id',
          columnNames: ['user_id'],
        }),
      );
    }

    // patient_profiles
    if (!(await queryRunner.getTable('patient_profiles'))) {
      await queryRunner.createTable(
        new Table({
          name: 'patient_profiles',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            { name: 'patient_id', type: 'uuid', isNullable: false },
            { name: 'name', type: 'varchar', length: '255', isNullable: false },
            {
              name: 'profile_image',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            { name: 'address', type: 'text', isNullable: true },
            {
              name: 'phone_number',
              type: 'varchar',
              length: '20',
              isNullable: true,
            },
            { name: 'gender', type: 'varchar', length: '20', isNullable: true },
            { name: 'age', type: 'integer', isNullable: true },
            { name: 'emergency_contact', type: 'jsonb', isNullable: true },
            {
              name: 'onboarding_status',
              type: 'varchar',
              length: '10',
              default: "'pending'",
            },
            {
              name: 'first_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'middle_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'last_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            { name: 'date_of_birth', type: 'date', isNullable: true },
            {
              name: 'social_security_number',
              type: 'varchar',
              length: '11',
              isNullable: true,
            },
            {
              name: 'marital_status',
              type: 'varchar',
              length: '20',
              isNullable: true,
            },
            { name: 'religion', type: 'varchar', length: '100', isNullable: true },
            {
              name: 'patient_address_street',
              type: 'varchar',
              length: '255',
              isNullable: true,
            },
            {
              name: 'patient_address_city',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'patient_address_state',
              type: 'varchar',
              length: '50',
              isNullable: true,
            },
            {
              name: 'patient_address_zip',
              type: 'varchar',
              length: '10',
              isNullable: true,
            },
            { name: 'home_phone', type: 'varchar', length: '20', isNullable: true },
            { name: 'work_phone', type: 'varchar', length: '20', isNullable: true },
            {
              name: 'email_address',
              type: 'varchar',
              length: '254',
              isNullable: true,
            },
            {
              name: 'emergency_contact_first_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'emergency_contact_last_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'emergency_contact_relationship',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'emergency_contact_phone',
              type: 'varchar',
              length: '20',
              isNullable: true,
            },
            {
              name: 'emergency_contact_address',
              type: 'text',
              isNullable: true,
            },
            {
              name: 'next_of_kin_first_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'next_of_kin_last_name',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'next_of_kin_relationship',
              type: 'varchar',
              length: '100',
              isNullable: true,
            },
            {
              name: 'next_of_kin_phone',
              type: 'varchar',
              length: '20',
              isNullable: true,
            },
            {
              name: 'next_of_kin_address',
              type: 'text',
              isNullable: true,
            },
            {
              name: 'primary_insurance_provider',
              type: 'varchar',
              length: '200',
              isNullable: true,
            },
            {
              name: 'primary_member_id',
              type: 'varchar',
              length: '50',
              isNullable: true,
            },
            {
              name: 'primary_group_id',
              type: 'varchar',
              length: '50',
              isNullable: true,
            },
            {
              name: 'secondary_insurance_provider',
              type: 'varchar',
              length: '200',
              isNullable: true,
            },
            {
              name: 'secondary_member_id',
              type: 'varchar',
              length: '50',
              isNullable: true,
            },
            {
              name: 'income_source',
              type: 'varchar',
              length: '20',
              isNullable: true,
            },
            {
              name: 'medicaid_eligibility',
              type: 'boolean',
              default: false,
            },
            {
              name: 'created_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
            {
              name: 'updated_at',
              type: 'timestamp',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );
      await queryRunner.createForeignKey(
        'patient_profiles',
        new TableForeignKey({
          columnNames: ['patient_id'],
          referencedTableName: 'patients',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
          name: 'fk_patient_profiles_patient_id',
        }),
      );
      await queryRunner.createIndex(
        'patient_profiles',
        new TableIndex({
          name: 'UQ_patient_profiles_patient_id',
          columnNames: ['patient_id'],
          isUnique: true,
        }),
      );
      await queryRunner.createIndex(
        'patient_profiles',
        new TableIndex({ name: 'IDX_patient_profiles_first_name', columnNames: ['first_name'] }),
      );
      await queryRunner.createIndex(
        'patient_profiles',
        new TableIndex({ name: 'IDX_patient_profiles_last_name', columnNames: ['last_name'] }),
      );
      await queryRunner.createIndex(
        'patient_profiles',
        new TableIndex({ name: 'IDX_patient_profiles_date_of_birth', columnNames: ['date_of_birth'] }),
      );
      await queryRunner.createIndex(
        'patient_profiles',
        new TableIndex({
          name: 'IDX_patient_profiles_social_security_number',
          columnNames: ['social_security_number'],
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const dropIfExists = async (name: string) => {
      if (await queryRunner.getTable(name)) {
        await queryRunner.dropTable(name, true);
      }
    };
    await dropIfExists('patient_profiles');
    await dropIfExists('patients');
    await dropIfExists('organizations');
    await dropIfExists('organization_types');
  }
}
