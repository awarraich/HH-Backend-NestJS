import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateHrDocumentTypesTable20260226100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'hr_document_types',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'code', type: 'varchar', length: '20', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: false },
          {
            name: 'has_expiration',
            type: 'boolean',
            default: false,
            isNullable: false,
          },
          {
            name: 'is_required',
            type: 'boolean',
            default: false,
            isNullable: false,
          },
          { name: 'category', type: 'varchar', length: '50', isNullable: true },
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
      'hr_document_types',
      new TableUnique({
        name: 'uq_hr_document_types_organization_id_code',
        columnNames: ['organization_id', 'code'],
      }),
    );

    await queryRunner.createForeignKey(
      'hr_document_types',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_hr_document_types_organization_id',
      }),
    );

    await queryRunner.createIndex(
      'hr_document_types',
      new TableIndex({
        name: 'idx_hr_document_types_organization_id',
        columnNames: ['organization_id'],
      }),
    );

    await queryRunner.createIndex(
      'hr_document_types',
      new TableIndex({
        name: 'idx_hr_document_types_organization_id_is_active',
        columnNames: ['organization_id', 'is_active'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'hr_document_types',
      'idx_hr_document_types_organization_id_is_active',
    );
    await queryRunner.dropIndex('hr_document_types', 'idx_hr_document_types_organization_id');
    await queryRunner.dropForeignKey('hr_document_types', 'fk_hr_document_types_organization_id');
    await queryRunner.dropTable('hr_document_types', true);
  }
}
