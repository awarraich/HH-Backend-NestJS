import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
} from 'typeorm';

/**
 * Offer Letter Assignment system — per-offer, per-employee isolated copies of
 * Document Workflow templates. Replaces the legacy `offer_letter_signing_tokens`
 * flow with a proper template-snapshot + role-assignment model.
 *
 * Tables:
 *   - offer_letter_assignments        (one row per offer sent to one application)
 *   - offer_letter_assignment_roles   (which user fills which template role)
 *   - offer_letter_field_values       (per-field filled values, unique per assignment)
 *
 * The legacy `offer_letter_signing_tokens` table is dropped — the old
 * /offer-letter/sign/:token flow is replaced by /offer-letter/fill/:token.
 */
export class CreateOfferLetterAssignmentTables20260416200000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ── offer_letter_assignments ──────────────────────────────────────────────
    if (!(await queryRunner.getTable('offer_letter_assignments'))) {
      await queryRunner.createTable(
        new Table({
          name: 'offer_letter_assignments',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            { name: 'organization_id', type: 'uuid', isNullable: false },
            { name: 'job_application_id', type: 'uuid', isNullable: false },
            { name: 'template_id', type: 'uuid', isNullable: false },
            { name: 'template_snapshot', type: 'jsonb', isNullable: false },
            {
              name: 'status',
              type: 'varchar',
              length: '20',
              default: "'draft'",
              isNullable: false,
            },
            { name: 'sent_at', type: 'timestamptz', isNullable: true },
            { name: 'completed_at', type: 'timestamptz', isNullable: true },
            { name: 'created_by', type: 'uuid', isNullable: true },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
            },
            {
              name: 'updated_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );

      await queryRunner.createForeignKey(
        'offer_letter_assignments',
        new TableForeignKey({
          columnNames: ['job_application_id'],
          referencedTableName: 'job_applications',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
      await queryRunner.createForeignKey(
        'offer_letter_assignments',
        new TableForeignKey({
          columnNames: ['template_id'],
          referencedTableName: 'competency_templates',
          referencedColumnNames: ['id'],
          onDelete: 'RESTRICT',
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignments',
        new TableIndex({
          name: 'idx_ola_organization',
          columnNames: ['organization_id'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignments',
        new TableIndex({
          name: 'idx_ola_application',
          columnNames: ['job_application_id'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignments',
        new TableIndex({
          name: 'idx_ola_template',
          columnNames: ['template_id'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignments',
        new TableIndex({
          name: 'idx_ola_org_status',
          columnNames: ['organization_id', 'status'],
        }),
      );
    }

    // ── offer_letter_assignment_roles ─────────────────────────────────────────
    if (!(await queryRunner.getTable('offer_letter_assignment_roles'))) {
      await queryRunner.createTable(
        new Table({
          name: 'offer_letter_assignment_roles',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            { name: 'assignment_id', type: 'uuid', isNullable: false },
            { name: 'role_id', type: 'uuid', isNullable: false },
            { name: 'user_id', type: 'uuid', isNullable: false },
            {
              name: 'recipient_type',
              type: 'varchar',
              length: '32',
              isNullable: false,
            },
            {
              name: 'fill_token',
              type: 'varchar',
              length: '128',
              isNullable: true,
              isUnique: true,
            },
            {
              name: 'fill_token_expires_at',
              type: 'timestamptz',
              isNullable: true,
            },
            { name: 'completed_at', type: 'timestamptz', isNullable: true },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
            },
            {
              name: 'updated_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );

      await queryRunner.createForeignKey(
        'offer_letter_assignment_roles',
        new TableForeignKey({
          columnNames: ['assignment_id'],
          referencedTableName: 'offer_letter_assignments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
      await queryRunner.createForeignKey(
        'offer_letter_assignment_roles',
        new TableForeignKey({
          columnNames: ['role_id'],
          referencedTableName: 'document_workflow_roles',
          referencedColumnNames: ['id'],
          onDelete: 'RESTRICT',
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignment_roles',
        new TableIndex({
          name: 'idx_olar_assignment',
          columnNames: ['assignment_id'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignment_roles',
        new TableIndex({
          name: 'idx_olar_user',
          columnNames: ['user_id'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignment_roles',
        new TableIndex({
          name: 'idx_olar_fill_token',
          columnNames: ['fill_token'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_assignment_roles',
        new TableIndex({
          name: 'uq_olar_assignment_role_user',
          columnNames: ['assignment_id', 'role_id', 'user_id'],
          isUnique: true,
        }),
      );
    }

    // ── offer_letter_field_values ─────────────────────────────────────────────
    if (!(await queryRunner.getTable('offer_letter_field_values'))) {
      await queryRunner.createTable(
        new Table({
          name: 'offer_letter_field_values',
          columns: [
            {
              name: 'id',
              type: 'uuid',
              isPrimary: true,
              default: 'uuid_generate_v4()',
            },
            { name: 'assignment_id', type: 'uuid', isNullable: false },
            {
              name: 'field_id',
              type: 'varchar',
              length: '255',
              isNullable: false,
            },
            { name: 'filled_by_user_id', type: 'uuid', isNullable: true },
            { name: 'filled_by_role_id', type: 'uuid', isNullable: true },
            { name: 'value_text', type: 'text', isNullable: true },
            { name: 'value_json', type: 'jsonb', isNullable: true },
            {
              name: 'created_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
            },
            {
              name: 'updated_at',
              type: 'timestamptz',
              default: 'CURRENT_TIMESTAMP',
            },
          ],
        }),
        true,
      );

      await queryRunner.createForeignKey(
        'offer_letter_field_values',
        new TableForeignKey({
          columnNames: ['assignment_id'],
          referencedTableName: 'offer_letter_assignments',
          referencedColumnNames: ['id'],
          onDelete: 'CASCADE',
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_field_values',
        new TableIndex({
          name: 'idx_olfv_assignment',
          columnNames: ['assignment_id'],
        }),
      );
      await queryRunner.createIndex(
        'offer_letter_field_values',
        new TableIndex({
          name: 'uq_olfv_assignment_field',
          columnNames: ['assignment_id', 'field_id'],
          isUnique: true,
        }),
      );
    }

    // ── Drop legacy offer_letter_signing_tokens (no longer used) ──────────────
    const legacy = await queryRunner.getTable('offer_letter_signing_tokens');
    if (legacy) {
      for (const fk of legacy.foreignKeys) {
        await queryRunner.dropForeignKey('offer_letter_signing_tokens', fk);
      }
      await queryRunner.dropTable('offer_letter_signing_tokens');
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('offer_letter_field_values', true);
    await queryRunner.dropTable('offer_letter_assignment_roles', true);
    await queryRunner.dropTable('offer_letter_assignments', true);

    // Recreate the legacy table shape for safety on rollback.
    await queryRunner.createTable(
      new Table({
        name: 'offer_letter_signing_tokens',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'uuid_generate_v4()',
          },
          {
            name: 'token',
            type: 'varchar',
            length: '128',
            isNullable: false,
            isUnique: true,
          },
          { name: 'job_application_id', type: 'uuid', isNullable: false },
          { name: 'candidate_email', type: 'varchar', length: '255' },
          { name: 'candidate_name', type: 'varchar', length: '255' },
          { name: 'job_title', type: 'varchar', length: '500' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'pdf_url', type: 'varchar', length: '2048' },
          { name: 'signature_position', type: 'jsonb', isNullable: true },
          { name: 'expires_at', type: 'timestamp', isNullable: false },
          { name: 'used_at', type: 'timestamp', isNullable: true },
          { name: 'signed_pdf_url', type: 'varchar', length: '2048', isNullable: true },
          { name: 'audit_trail', type: 'jsonb', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );
  }
}
