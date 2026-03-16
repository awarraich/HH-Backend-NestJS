import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

/**
 * Company profile / organization details (public-facing profile: name, logo, hours, services, gallery, videos, packages, reviews).
 * Gallery and videos store either file_path (backend upload) or url (external).
 */
export class CreateOrganizationCompanyProfilesTable20260317000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'organization_company_profiles',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'company_name', type: 'varchar', length: '255', isNullable: true },
          { name: 'logo', type: 'varchar', length: '500', isNullable: true },
          { name: 'cover_image', type: 'varchar', length: '500', isNullable: true },
          { name: 'cover_images', type: 'jsonb', isNullable: true, default: "'[]'::jsonb" },
          { name: 'organization_type', type: 'varchar', length: '50', isNullable: true },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'phone', type: 'varchar', length: '50', isNullable: true },
          { name: 'fax', type: 'varchar', length: '50', isNullable: true },
          { name: 'email', type: 'varchar', length: '255', isNullable: true },
          { name: 'website', type: 'varchar', length: '500', isNullable: true },
          { name: 'address', type: 'varchar', length: '500', isNullable: true },
          { name: 'business_hours', type: 'jsonb', isNullable: true },
          { name: 'service_area', type: 'jsonb', isNullable: true },
          { name: 'coverage_radius', type: 'varchar', length: '100', isNullable: true },
          { name: 'selected_services', type: 'jsonb', isNullable: true },
          { name: 'licenses', type: 'jsonb', isNullable: true },
          { name: 'certifications', type: 'jsonb', isNullable: true },
          { name: 'gallery', type: 'jsonb', isNullable: true, default: "'[]'::jsonb" },
          { name: 'videos', type: 'jsonb', isNullable: true, default: "'[]'::jsonb" },
          { name: 'packages', type: 'jsonb', isNullable: true, default: "'[]'::jsonb" },
          { name: 'specialty_services', type: 'jsonb', isNullable: true },
          { name: 'accepted_insurance', type: 'jsonb', isNullable: true },
          { name: 'amenities', type: 'jsonb', isNullable: true },
          { name: 'room_types', type: 'jsonb', isNullable: true },
          { name: 'equipment_catalog', type: 'jsonb', isNullable: true },
          { name: 'transport_types', type: 'jsonb', isNullable: true },
          { name: 'availability_status', type: 'varchar', length: '20', isNullable: true },
          { name: 'rating', type: 'decimal', precision: 3, scale: 2, isNullable: true },
          { name: 'review_count', type: 'integer', isNullable: true },
          { name: 'reviews', type: 'jsonb', isNullable: true, default: "'[]'::jsonb" },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'organization_company_profiles',
      new TableUnique({
        name: 'uq_organization_company_profiles_organization_id',
        columnNames: ['organization_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'organization_company_profiles',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_organization_company_profiles_organization_id',
      }),
    );

    await queryRunner.createIndex(
      'organization_company_profiles',
      new TableIndex({
        name: 'idx_organization_company_profiles_organization_id',
        columnNames: ['organization_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'organization_company_profiles',
      'idx_organization_company_profiles_organization_id',
    );
    await queryRunner.dropForeignKey(
      'organization_company_profiles',
      'fk_organization_company_profiles_organization_id',
    );
    await queryRunner.dropTable('organization_company_profiles', true);
  }
}
