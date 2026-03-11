import { MigrationInterface, QueryRunner, Table, TableIndex, TableForeignKey } from 'typeorm';

/**
 * Creates job_applications table for the job apply flow.
 */
export class CreateJobApplicationsTable20260307000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.getTable('job_applications')) {
      return;
    }
    await queryRunner.createTable(
      new Table({
        name: 'job_applications',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'uuid_generate_v4()',
          },
          { name: 'job_posting_id', type: 'uuid', isNullable: false },
          { name: 'applicant_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'applicant_email', type: 'varchar', length: '255', isNullable: false },
          { name: 'applicant_phone', type: 'varchar', length: '50', isNullable: true },
          { name: 'notes', type: 'text', isNullable: true },
          { name: 'submitted_fields', type: 'jsonb', isNullable: true },
          {
            name: 'status',
            type: 'varchar',
            length: '50',
            isNullable: false,
            default: "'pending'",
          },
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
      'job_applications',
      new TableIndex({
        name: 'IDX_job_applications_job_posting_id',
        columnNames: ['job_posting_id'],
      }),
    );
    await queryRunner.createForeignKey(
      'job_applications',
      new TableForeignKey({
        columnNames: ['job_posting_id'],
        referencedTableName: 'job_postings',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('job_applications');
    if (table) {
      const fk = table.foreignKeys.find((fk) => fk.columnNames.indexOf('job_posting_id') !== -1);
      if (fk) await queryRunner.dropForeignKey('job_applications', fk);
      await queryRunner.dropTable('job_applications');
    }
  }
}
