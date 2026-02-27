import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateBlogsTable1708000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'blogs',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'title',
            type: 'varchar',
            length: '200',
          },
          {
            name: 'slug',
            type: 'varchar',
            length: '200',
            isUnique: true,
          },
          {
            name: 'content',
            type: 'text',
          },
          {
            name: 'excerpt',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'author_id',
            type: 'uuid',
            isNullable: true,
          },
          {
            name: 'featured_image',
            type: 'varchar',
            length: '500',
            isNullable: true,
          },
          {
            name: 'is_published',
            type: 'boolean',
            default: false,
          },
          {
            name: 'published_at',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'category',
            type: 'varchar',
            length: '100',
            isNullable: true,
          },
          {
            name: 'tags',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
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
        foreignKeys: [
          {
            name: 'blogs_author_id_fkey',
            columnNames: ['author_id'],
            referencedTableName: 'users',
            referencedColumnNames: ['id'],
            onDelete: 'SET NULL',
          },
        ],
      }),
      true,
    );

    // Create indexes
    await queryRunner.createIndex(
      'blogs',
      new TableIndex({
        name: 'IDX_blogs_slug',
        columnNames: ['slug'],
        isUnique: true,
      }),
    );

    await queryRunner.createIndex(
      'blogs',
      new TableIndex({
        name: 'IDX_blogs_is_published',
        columnNames: ['is_published'],
      }),
    );

    await queryRunner.createIndex(
      'blogs',
      new TableIndex({
        name: 'IDX_blogs_published_at',
        columnNames: ['published_at'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('blogs');
  }
}
