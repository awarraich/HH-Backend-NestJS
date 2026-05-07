import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableColumn,
  TableForeignKey,
  TableIndex,
} from 'typeorm';

/**
 * Phase 3: template versioning. Freezes the template schema (the
 * `document_fields` JSONB and friends) at publish time so historical
 * `document_field_values` always render against the schema the user
 * actually saw — even after an admin edits the template later.
 *
 * Shape:
 *   competency_templates                  → mutable draft + pointer to
 *                                            current published version
 *   competency_template_versions          → frozen snapshots; one row per
 *                                            publish (version_number is
 *                                            monotonic per template)
 *   document_template_user_assignments    → pins the version it was
 *                                            assigned against
 *   document_field_values                 → pinned to the version the
 *                                            user filled
 *
 * Lifecycle (handled in the service layer):
 *   - On template create, immediately publish v1 so the template is
 *     assignable.
 *   - On template update, mutate the draft only — `current_version_id`
 *     stays unchanged. Existing assignments keep rendering against
 *     their pinned version.
 *   - Admin clicks "Publish" → snapshot current draft into a new
 *     version row, bump `current_version_id`. Existing assignments are
 *     untouched.
 *
 * Backfill walks every existing template and inserts a v1 snapshot,
 * then plumbs `template_version_id` into every existing assignment and
 * field-value row before the NOT NULL + FK constraints land. Idempotent
 * — safe to re-run if it fails partway.
 */
export class AddTemplateVersioning20260507140000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // ─── 1. Create competency_template_versions ───
    if (!(await queryRunner.hasTable('competency_template_versions'))) {
      await queryRunner.createTable(
        new Table({
          name: 'competency_template_versions',
          columns: [
            { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
            { name: 'template_id', type: 'uuid', isNullable: false },
            { name: 'version_number', type: 'int', isNullable: false },
            { name: 'document_fields', type: 'jsonb', default: "'[]'", isNullable: false },
            { name: 'roles', type: 'jsonb', default: "'[]'", isNullable: false },
            { name: 'pdf_file_key', type: 'varchar', length: '500', isNullable: true },
            { name: 'pdf_original_name', type: 'varchar', length: '255', isNullable: true },
            { name: 'pdf_size_bytes', type: 'integer', isNullable: true },
            { name: 'published_at', type: 'timestamptz', default: 'now()', isNullable: false },
            { name: 'published_by', type: 'uuid', isNullable: true },
          ],
          uniques: [{ columnNames: ['template_id', 'version_number'] }],
          foreignKeys: [
            {
              columnNames: ['template_id'],
              referencedTableName: 'competency_templates',
              referencedColumnNames: ['id'],
              onDelete: 'CASCADE',
            },
          ],
        }),
        true,
      );
      await queryRunner.createIndex(
        'competency_template_versions',
        new TableIndex({ name: 'idx_ctv_template_id', columnNames: ['template_id'] }),
      );
    }

    // ─── 2. Add current_version_id pointer to competency_templates ───
    if (!(await queryRunner.hasColumn('competency_templates', 'current_version_id'))) {
      await queryRunner.addColumn(
        'competency_templates',
        new TableColumn({ name: 'current_version_id', type: 'uuid', isNullable: true }),
      );
    }

    // ─── 3. Add template_version_id columns (nullable initially so backfill can fill them) ───
    if (
      !(await queryRunner.hasColumn(
        'document_template_user_assignments',
        'template_version_id',
      ))
    ) {
      await queryRunner.addColumn(
        'document_template_user_assignments',
        new TableColumn({ name: 'template_version_id', type: 'uuid', isNullable: true }),
      );
    }
    if (!(await queryRunner.hasColumn('document_field_values', 'template_version_id'))) {
      await queryRunner.addColumn(
        'document_field_values',
        new TableColumn({ name: 'template_version_id', type: 'uuid', isNullable: true }),
      );
    }

    // ─── 4. Backfill v1 snapshots for every existing template ───
    // ON CONFLICT keeps this idempotent — re-running won't double-insert.
    await queryRunner.query(`
      INSERT INTO competency_template_versions
        (template_id, version_number, document_fields, roles,
         pdf_file_key, pdf_original_name, pdf_size_bytes,
         published_at, published_by)
      SELECT
        id,
        1,
        document_fields,
        roles,
        pdf_file_key,
        pdf_original_name,
        pdf_size_bytes,
        COALESCE(updated_at, created_at, now()),
        created_by
      FROM competency_templates
      ON CONFLICT (template_id, version_number) DO NOTHING;
    `);

    // ─── 5. Point each template at its v1 (only those still null) ───
    await queryRunner.query(`
      UPDATE competency_templates ct
      SET current_version_id = v.id
      FROM competency_template_versions v
      WHERE v.template_id = ct.id
        AND v.version_number = 1
        AND ct.current_version_id IS NULL;
    `);

    // ─── 6. Backfill assignments + values to v1 ───
    await queryRunner.query(`
      UPDATE document_template_user_assignments dtua
      SET template_version_id = ct.current_version_id
      FROM competency_templates ct
      WHERE ct.id = dtua.template_id
        AND dtua.template_version_id IS NULL
        AND ct.current_version_id IS NOT NULL;
    `);
    await queryRunner.query(`
      UPDATE document_field_values dfv
      SET template_version_id = ct.current_version_id
      FROM competency_templates ct
      WHERE ct.id = dfv.template_id
        AND dfv.template_version_id IS NULL
        AND ct.current_version_id IS NOT NULL;
    `);

    // ─── 7. NOT NULL + FK constraints after backfill ───
    // Wrapped in DO blocks so re-runs after a partial first run don't
    // explode on "constraint already exists".
    await queryRunner.query(`
      DO $$ BEGIN
        ALTER TABLE document_template_user_assignments
          ALTER COLUMN template_version_id SET NOT NULL;
      EXCEPTION WHEN others THEN NULL; END $$;
    `);
    await queryRunner.query(`
      DO $$ BEGIN
        ALTER TABLE document_field_values
          ALTER COLUMN template_version_id SET NOT NULL;
      EXCEPTION WHEN others THEN NULL; END $$;
    `);

    // Add FKs only if not already present (named, so we can probe them).
    const dtuaFkExists = await queryRunner.query(`
      SELECT 1 FROM pg_constraint WHERE conname = 'fk_dtua_template_version_id';
    `);
    if (dtuaFkExists.length === 0) {
      await queryRunner.createForeignKey(
        'document_template_user_assignments',
        new TableForeignKey({
          name: 'fk_dtua_template_version_id',
          columnNames: ['template_version_id'],
          referencedTableName: 'competency_template_versions',
          referencedColumnNames: ['id'],
          onDelete: 'RESTRICT',
        }),
      );
    }
    const dfvFkExists = await queryRunner.query(`
      SELECT 1 FROM pg_constraint WHERE conname = 'fk_dfv_template_version_id';
    `);
    if (dfvFkExists.length === 0) {
      await queryRunner.createForeignKey(
        'document_field_values',
        new TableForeignKey({
          name: 'fk_dfv_template_version_id',
          columnNames: ['template_version_id'],
          referencedTableName: 'competency_template_versions',
          referencedColumnNames: ['id'],
          onDelete: 'RESTRICT',
        }),
      );
    }

    // current_version_id FK on competency_templates (set NULL on
    // delete since the version has CASCADE on template — which would
    // mean a deleted template wipes its versions which would fail this
    // FK; SET NULL keeps the template row stable but it won't matter
    // because the CASCADE chain wipes the template too).
    const ctFkExists = await queryRunner.query(`
      SELECT 1 FROM pg_constraint WHERE conname = 'fk_ct_current_version_id';
    `);
    if (ctFkExists.length === 0) {
      await queryRunner.createForeignKey(
        'competency_templates',
        new TableForeignKey({
          name: 'fk_ct_current_version_id',
          columnNames: ['current_version_id'],
          referencedTableName: 'competency_template_versions',
          referencedColumnNames: ['id'],
          onDelete: 'SET NULL',
        }),
      );
    }

    // ─── 8. Swap unique constraint on document_field_values ───
    // Old: (template_id, field_id, user_id) — prevented re-fill across
    // versions. New: (template_version_id, field_id, user_id) — lets
    // the same user fill v1 (rejected) AND v2 (after edits) cleanly.
    //
    // Postgres auto-named the original constraint
    // `document_field_values_template_id_field_id_user_id_key` (its
    // standard suffix for inline UNIQUE). Drop with IF EXISTS so a
    // future rename doesn't break the migration.
    await queryRunner.query(`
      ALTER TABLE document_field_values
      DROP CONSTRAINT IF EXISTS document_field_values_template_id_field_id_user_id_key;
    `);
    const dfvUniqueExists = await queryRunner.query(`
      SELECT 1 FROM pg_constraint WHERE conname = 'uq_dfv_version_field_user';
    `);
    if (dfvUniqueExists.length === 0) {
      await queryRunner.query(`
        ALTER TABLE document_field_values
        ADD CONSTRAINT uq_dfv_version_field_user
        UNIQUE (template_version_id, field_id, user_id);
      `);
    }

    // ─── 9. Indexes for the new version-scoped read paths ───
    await queryRunner.createIndex(
      'document_template_user_assignments',
      new TableIndex({
        name: 'idx_dtua_template_version_id',
        columnNames: ['template_version_id'],
      }),
    );
    await queryRunner.createIndex(
      'document_field_values',
      new TableIndex({
        name: 'idx_dfv_template_version_id',
        columnNames: ['template_version_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Reverse in opposite order. Drop FKs / indexes / constraints
    // before dropping the columns or table.
    await queryRunner.query(`
      ALTER TABLE document_field_values
      DROP CONSTRAINT IF EXISTS uq_dfv_version_field_user;
    `);
    // Best-effort restore of the original unique constraint shape.
    await queryRunner.query(`
      DO $$ BEGIN
        ALTER TABLE document_field_values
        ADD CONSTRAINT document_field_values_template_id_field_id_user_id_key
        UNIQUE (template_id, field_id, user_id);
      EXCEPTION WHEN others THEN NULL; END $$;
    `);

    await queryRunner
      .dropIndex('document_field_values', 'idx_dfv_template_version_id')
      .catch(() => {});
    await queryRunner
      .dropIndex('document_template_user_assignments', 'idx_dtua_template_version_id')
      .catch(() => {});

    await queryRunner.query(`
      ALTER TABLE competency_templates DROP CONSTRAINT IF EXISTS fk_ct_current_version_id;
    `);
    await queryRunner.query(`
      ALTER TABLE document_field_values DROP CONSTRAINT IF EXISTS fk_dfv_template_version_id;
    `);
    await queryRunner.query(`
      ALTER TABLE document_template_user_assignments DROP CONSTRAINT IF EXISTS fk_dtua_template_version_id;
    `);

    if (await queryRunner.hasColumn('document_field_values', 'template_version_id')) {
      await queryRunner.dropColumn('document_field_values', 'template_version_id');
    }
    if (
      await queryRunner.hasColumn('document_template_user_assignments', 'template_version_id')
    ) {
      await queryRunner.dropColumn('document_template_user_assignments', 'template_version_id');
    }
    if (await queryRunner.hasColumn('competency_templates', 'current_version_id')) {
      await queryRunner.dropColumn('competency_templates', 'current_version_id');
    }
    if (await queryRunner.hasTable('competency_template_versions')) {
      await queryRunner.dropTable('competency_template_versions', true);
    }
  }
}
