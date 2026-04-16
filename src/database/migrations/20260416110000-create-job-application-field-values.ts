import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
} from 'typeorm';

/**
 * Normalizes `job_applications.submitted_fields` JSONB into a dedicated per-row table.
 *
 * Each form-field answer becomes its own row keyed by (application_id, field_key). Plain
 * strings live in `value_text`; structured values (file refs, arrays, nested objects)
 * live in `value_json`.
 *
 * Existing rows are backfilled from the JSONB blob so no data is lost. The original
 * `submitted_fields` column is left in place for one release as a safety net — a
 * follow-up migration can drop it once the frontend fully switches over.
 */
export class CreateJobApplicationFieldValues20260416110000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'job_application_field_values',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'uuid_generate_v4()',
          },
          { name: 'application_id', type: 'uuid', isNullable: false },
          { name: 'field_key', type: 'varchar', length: '255', isNullable: false },
          { name: 'field_label', type: 'varchar', length: '500', isNullable: true },
          { name: 'value_text', type: 'text', isNullable: true },
          { name: 'value_json', type: 'jsonb', isNullable: true },
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
      'job_application_field_values',
      new TableForeignKey({
        columnNames: ['application_id'],
        referencedTableName: 'job_applications',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createIndex(
      'job_application_field_values',
      new TableIndex({
        name: 'idx_app_field_values_application',
        columnNames: ['application_id'],
      }),
    );

    // Uniqueness so each (application, field_key) has at most one row — makes upserts trivial.
    await queryRunner.createIndex(
      'job_application_field_values',
      new TableIndex({
        name: 'idx_app_field_values_app_field_unique',
        columnNames: ['application_id', 'field_key'],
        isUnique: true,
      }),
    );

    // ---- Backfill from existing submitted_fields JSONB ------------------------------
    // For each application, explode every top-level key of submitted_fields into a row.
    // Plain strings → value_text; everything else → value_json.
    await queryRunner.query(`
      INSERT INTO job_application_field_values
        (application_id, field_key, value_text, value_json, created_at, updated_at)
      SELECT
        ja.id AS application_id,
        kv.key AS field_key,
        CASE
          WHEN jsonb_typeof(kv.value) = 'string' THEN kv.value #>> '{}'
          ELSE NULL
        END AS value_text,
        CASE
          WHEN jsonb_typeof(kv.value) = 'string' THEN NULL
          ELSE kv.value
        END AS value_json,
        ja.created_at,
        ja.created_at
      FROM job_applications ja
      CROSS JOIN LATERAL jsonb_each(COALESCE(ja.submitted_fields, '{}'::jsonb)) AS kv(key, value)
      ON CONFLICT DO NOTHING;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('job_application_field_values', true);
  }
}
