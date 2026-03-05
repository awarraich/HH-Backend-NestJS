import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateInserviceTrainingsTable20260305120000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'inservice_trainings',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'code', type: 'varchar', length: '20', isNullable: false },
          { name: 'title', type: 'varchar', length: '255', isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          {
            name: 'completion_frequency',
            type: 'varchar',
            length: '50',
            isNullable: false,
          },
          { name: 'expiry_months', type: 'integer', isNullable: true },
          {
            name: 'pdf_file_name',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'pdf_file_path',
            type: 'varchar',
            length: '500',
            isNullable: true,
          },
          {
            name: 'pdf_file_size_bytes',
            type: 'bigint',
            isNullable: true,
          },
          {
            name: 'video_url',
            type: 'varchar',
            length: '2048',
            isNullable: true,
          },
          {
            name: 'sort_order',
            type: 'integer',
            default: 0,
            isNullable: false,
          },
          {
            name: 'is_active',
            type: 'boolean',
            default: true,
            isNullable: false,
          },
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
      'inservice_trainings',
      new TableUnique({
        name: 'uq_inservice_trainings_organization_id_code',
        columnNames: ['organization_id', 'code'],
      }),
    );

    await queryRunner.query(
      `ALTER TABLE inservice_trainings ADD CONSTRAINT chk_inservice_trainings_content
       CHECK (pdf_file_path IS NOT NULL OR video_url IS NOT NULL)`,
    );

    await queryRunner.createForeignKey(
      'inservice_trainings',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_inservice_trainings_organization_id',
      }),
    );

    await queryRunner.createIndex(
      'inservice_trainings',
      new TableIndex({
        name: 'idx_inservice_trainings_organization_id',
        columnNames: ['organization_id'],
      }),
    );

    await queryRunner.createIndex(
      'inservice_trainings',
      new TableIndex({
        name: 'idx_inservice_trainings_organization_id_is_active',
        columnNames: ['organization_id', 'is_active'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE inservice_trainings DROP CONSTRAINT IF EXISTS chk_inservice_trainings_content`,
    );
    await queryRunner.dropIndex(
      'inservice_trainings',
      'idx_inservice_trainings_organization_id_is_active',
    );
    await queryRunner.dropIndex(
      'inservice_trainings',
      'idx_inservice_trainings_organization_id',
    );
    await queryRunner.dropForeignKey(
      'inservice_trainings',
      'fk_inservice_trainings_organization_id',
    );
    await queryRunner.dropTable('inservice_trainings', true);
  }
}
