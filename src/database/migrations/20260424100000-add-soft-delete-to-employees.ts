import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

/**
 * Switch the employees table from hard-delete to soft-delete.
 *   - `deleted_at`  — when non-null, the row is deleted from HR's POV
 *   - `deleted_by`  — user_id of the admin/HR who terminated the employee
 *   - `deletion_reason` — free-text reason captured at delete time (audit)
 *
 * The service layer replaces the DELETE with an UPDATE setting these
 * columns, and every employee-read path adds `WHERE deleted_at IS NULL`.
 *
 * We can't enforce "deleted_at IS NULL" as part of the existing
 * (user_id, organization_id) unique constraint without dropping + re-
 * creating it as a partial index. Done here so a re-hire after
 * soft-delete doesn't get blocked by the soft-deleted row.
 */
export class AddSoftDeleteToEmployees20260424100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'employees',
      new TableColumn({
        name: 'deleted_at',
        type: 'timestamptz',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'employees',
      new TableColumn({
        name: 'deleted_by',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'employees',
      new TableColumn({
        name: 'deletion_reason',
        type: 'text',
        isNullable: true,
      }),
    );

    await queryRunner.createIndex(
      'employees',
      new TableIndex({
        name: 'idx_employees_deleted_at',
        columnNames: ['deleted_at'],
      }),
    );

    // Replace the full (user_id, organization_id) unique constraint with a
    // partial unique index that only applies to live rows. This keeps the
    // "one employee per user per org" invariant for active records without
    // blocking the "fire, then re-hire" workflow.
    await queryRunner.query(`
      ALTER TABLE employees
        DROP CONSTRAINT IF EXISTS "UQ_employees_user_id_organization_id"
    `);
    // TypeORM auto-names unique constraints like UQ_<hash>; drop any
    // remaining ones targeting (user_id, organization_id) to be safe.
    // Cast `attname` (type `name`) to `text` so the equality check against
    // a plain text[] literal works — Postgres doesn't auto-coerce these.
    await queryRunner.query(`
      DO $$
      DECLARE r RECORD;
      BEGIN
        FOR r IN
          SELECT conname
          FROM pg_constraint
          WHERE conrelid = 'employees'::regclass
            AND contype = 'u'
            AND (
              SELECT array_agg(attname::text ORDER BY attname::text)
              FROM unnest(conkey) AS k
              JOIN pg_attribute a ON a.attrelid = conrelid AND a.attnum = k
            ) = ARRAY['organization_id', 'user_id']::text[]
        LOOP
          EXECUTE 'ALTER TABLE employees DROP CONSTRAINT ' || quote_ident(r.conname);
        END LOOP;
      END$$;
    `);
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS "uq_employees_user_org_active"
        ON employees (user_id, organization_id)
        WHERE deleted_at IS NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Restore the old hard constraint. If there are multiple soft-deleted
    // rows for the same (user, org) this will fail — we leave that alone
    // intentionally so the DBA is forced to decide which row wins.
    await queryRunner.query(`DROP INDEX IF EXISTS "uq_employees_user_org_active"`);
    await queryRunner.query(`
      ALTER TABLE employees
        ADD CONSTRAINT "UQ_employees_user_id_organization_id"
        UNIQUE (user_id, organization_id)
    `);
    await queryRunner.dropIndex('employees', 'idx_employees_deleted_at');
    await queryRunner.dropColumn('employees', 'deletion_reason');
    await queryRunner.dropColumn('employees', 'deleted_by');
    await queryRunner.dropColumn('employees', 'deleted_at');
  }
}
