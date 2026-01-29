import { MigrationInterface, QueryRunner, TableColumn, TableIndex } from 'typeorm';

export class AddGoogleIdToUsers20260128060000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add google_id column
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'google_id',
        type: 'varchar',
        length: '255',
        isNullable: true,
        isUnique: true,
      }),
    );

    // Add unique index for google_id (only for non-null values)
    await queryRunner.query(`
      CREATE UNIQUE INDEX "idx_users_google_id" 
      ON "users" ("google_id") 
      WHERE "google_id" IS NOT NULL
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop the index first
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_users_google_id"`);

    // Drop the column
    await queryRunner.dropColumn('users', 'google_id');
  }
}

