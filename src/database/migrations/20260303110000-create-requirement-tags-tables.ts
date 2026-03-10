import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
  TableUnique,
} from 'typeorm';

export class CreateRequirementTagsTables20260303110000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'requirement_tags',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'title', type: 'varchar', length: '255', isNullable: false },
          { name: 'category', type: 'varchar', length: '100', isNullable: false },
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

    await queryRunner.createForeignKey(
      'requirement_tags',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_requirement_tags_organization_id',
      }),
    );

    await queryRunner.createIndex(
      'requirement_tags',
      new TableIndex({
        name: 'idx_requirement_tags_organization_id',
        columnNames: ['organization_id'],
      }),
    );

    await queryRunner.createIndex(
      'requirement_tags',
      new TableIndex({
        name: 'idx_requirement_tags_organization_id_category',
        columnNames: ['organization_id', 'category'],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'requirement_document_types',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'requirement_tag_id', type: 'uuid', isNullable: false },
          { name: 'document_type_id', type: 'uuid', isNullable: false },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    await queryRunner.createUniqueConstraint(
      'requirement_document_types',
      new TableUnique({
        name: 'uq_requirement_document_types_tag_doctype',
        columnNames: ['requirement_tag_id', 'document_type_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'requirement_document_types',
      new TableForeignKey({
        columnNames: ['requirement_tag_id'],
        referencedTableName: 'requirement_tags',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_requirement_document_types_requirement_tag_id',
      }),
    );

    await queryRunner.createForeignKey(
      'requirement_document_types',
      new TableForeignKey({
        columnNames: ['document_type_id'],
        referencedTableName: 'hr_document_types',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_requirement_document_types_document_type_id',
      }),
    );

    await queryRunner.createIndex(
      'requirement_document_types',
      new TableIndex({
        name: 'idx_requirement_document_types_requirement_tag_id',
        columnNames: ['requirement_tag_id'],
      }),
    );

    await queryRunner.createIndex(
      'requirement_document_types',
      new TableIndex({
        name: 'idx_requirement_document_types_document_type_id',
        columnNames: ['document_type_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'requirement_document_types',
      'idx_requirement_document_types_document_type_id',
    );
    await queryRunner.dropIndex(
      'requirement_document_types',
      'idx_requirement_document_types_requirement_tag_id',
    );
    await queryRunner.dropForeignKey(
      'requirement_document_types',
      'fk_requirement_document_types_document_type_id',
    );
    await queryRunner.dropForeignKey(
      'requirement_document_types',
      'fk_requirement_document_types_requirement_tag_id',
    );
    await queryRunner.dropTable('requirement_document_types', true);

    await queryRunner.dropIndex(
      'requirement_tags',
      'idx_requirement_tags_organization_id_category',
    );
    await queryRunner.dropIndex('requirement_tags', 'idx_requirement_tags_organization_id');
    await queryRunner.dropForeignKey('requirement_tags', 'fk_requirement_tags_organization_id');
    await queryRunner.dropTable('requirement_tags', true);
  }
}
