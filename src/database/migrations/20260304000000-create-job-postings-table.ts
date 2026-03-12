import { MigrationInterface, QueryRunner, Table, TableIndex, TableForeignKey } from 'typeorm';

/**
 * Creates job_postings table for the job-management feature.
 */
export class CreateJobPostingsTable20260304000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.getTable('job_postings')) {
      return;
    }
    await queryRunner.createTable(
      new Table({
        name: 'job_postings',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'uuid_generate_v4()',
          },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'title', type: 'varchar', length: '500', isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'location', type: 'varchar', length: '255', isNullable: true },
          {
            name: 'location_type',
            type: 'varchar',
            length: '50',
            isNullable: true,
            default: "'in_person'",
          },
          { name: 'salary_range', type: 'varchar', length: '255', isNullable: true },
          { name: 'application_deadline', type: 'timestamp', isNullable: true },
          {
            name: 'status',
            type: 'varchar',
            length: '30',
            isNullable: false,
            default: "'active'",
          },
          { name: 'details', type: 'jsonb', isNullable: true },
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
    await queryRunner.createIndex(
      'job_postings',
      new TableIndex({
        name: 'IDX_job_postings_organization_id',
        columnNames: ['organization_id'],
      }),
    );
    await queryRunner.createIndex(
      'job_postings',
      new TableIndex({ name: 'IDX_job_postings_status', columnNames: ['status'] }),
    );
    await queryRunner.createIndex(
      'job_postings',
      new TableIndex({
        name: 'IDX_job_postings_organization_status',
        columnNames: ['organization_id', 'status'],
      }),
    );
    await queryRunner.createForeignKey(
      'job_postings',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('job_postings');
    if (table) {
      const fk = table.foreignKeys.find((fk) => fk.columnNames.indexOf('organization_id') !== -1);
      if (fk) await queryRunner.dropForeignKey('job_postings', fk);
      await queryRunner.dropTable('job_postings');
    }
  }
}
