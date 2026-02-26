import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class CreateDocumentChunksAndVector20260227100001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS vector');

    await queryRunner.createTable(
      new Table({
        name: 'document_chunks',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'document_id', type: 'uuid', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          {
            name: 'chunk_index',
            type: 'integer',
            isNullable: false,
          },
          { name: 'chunk_text', type: 'text', isNullable: false },
          { name: 'chunk_tokens', type: 'integer', isNullable: true },
          {
            name: 'embedding',
            type: 'vector(1536)',
            isNullable: true,
          },
          {
            name: 'metadata',
            type: 'jsonb',
            default: "'{}'",
            isNullable: false,
          },
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

    await queryRunner.createForeignKey(
      'document_chunks',
      new TableForeignKey({
        columnNames: ['document_id'],
        referencedTableName: 'employee_documents',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_document_chunks_document_id',
      }),
    );

    await queryRunner.createIndex(
      'document_chunks',
      new TableIndex({
        name: 'idx_document_chunks_document_id',
        columnNames: ['document_id'],
      }),
    );
    await queryRunner.createIndex(
      'document_chunks',
      new TableIndex({
        name: 'idx_document_chunks_organization_id',
        columnNames: ['organization_id'],
      }),
    );
    await queryRunner.createIndex(
      'document_chunks',
      new TableIndex({
        name: 'idx_document_chunks_employee_id',
        columnNames: ['employee_id'],
      }),
    );

    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS idx_document_chunks_embedding ON document_chunks USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      'DROP INDEX IF EXISTS idx_document_chunks_embedding',
    );
    await queryRunner.dropIndex(
      'document_chunks',
      'idx_document_chunks_employee_id',
    );
    await queryRunner.dropIndex(
      'document_chunks',
      'idx_document_chunks_organization_id',
    );
    await queryRunner.dropIndex(
      'document_chunks',
      'idx_document_chunks_document_id',
    );
    await queryRunner.dropForeignKey(
      'document_chunks',
      'fk_document_chunks_document_id',
    );
    await queryRunner.dropTable('document_chunks', true);
  }
}
