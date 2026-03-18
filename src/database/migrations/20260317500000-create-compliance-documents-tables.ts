import { MigrationInterface, QueryRunner, Table, TableIndex, TableForeignKey } from 'typeorm';

export class CreateComplianceDocumentsTables20260317500000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'organization_document_categories',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'name', type: 'varchar', length: '255', isNullable: false },
          { name: 'description', type: 'text', isNullable: true },
          { name: 'icon', type: 'varchar', length: '50', isNullable: true },
          { name: 'color', type: 'varchar', length: '20', isNullable: true },
          { name: 'sort_order', type: 'integer', default: 0, isNullable: false },
          { name: 'is_active', type: 'boolean', default: true, isNullable: false },
          { name: 'is_default', type: 'boolean', default: false, isNullable: false },
          { name: 'created_by', type: 'uuid', isNullable: true },
          { name: 'updated_by', type: 'uuid', isNullable: true },
          { name: 'created_at', type: 'timestamp with time zone', default: 'NOW()', isNullable: false },
          { name: 'updated_at', type: 'timestamp with time zone', default: 'NOW()', isNullable: false },
          { name: 'deleted_at', type: 'timestamp with time zone', isNullable: true },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'organization_document_categories',
      new TableForeignKey({
        name: 'fk_org_doc_cat_organization_id',
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createIndex(
      'organization_document_categories',
      new TableIndex({ name: 'idx_org_doc_cat_org', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'organization_document_categories',
      new TableIndex({ name: 'idx_org_doc_cat_active', columnNames: ['organization_id', 'is_active'] }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'organization_documents',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'category_id', type: 'uuid', isNullable: false },
          { name: 'document_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'file_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'file_path', type: 'varchar', length: '500', isNullable: false },
          { name: 'file_size_bytes', type: 'bigint', isNullable: true },
          { name: 'mime_type', type: 'varchar', length: '100', isNullable: true },
          { name: 'is_required', type: 'boolean', default: false, isNullable: false },
          { name: 'has_expiration', type: 'boolean', default: false, isNullable: false },
          { name: 'expiration_date', type: 'date', isNullable: true },
          { name: 'expiration_reminder_days', type: 'integer', default: 90, isNullable: false },
          { name: 'extracted_text', type: 'text', isNullable: true },
          { name: 'extraction_status', type: 'varchar', length: '20', default: "'pending'", isNullable: false },
          { name: 'extraction_error', type: 'text', isNullable: true },
          { name: 'uploaded_by', type: 'uuid', isNullable: true },
          { name: 'created_by', type: 'uuid', isNullable: true },
          { name: 'updated_by', type: 'uuid', isNullable: true },
          { name: 'created_at', type: 'timestamp with time zone', default: 'NOW()', isNullable: false },
          { name: 'updated_at', type: 'timestamp with time zone', default: 'NOW()', isNullable: false },
          { name: 'deleted_at', type: 'timestamp with time zone', isNullable: true },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'organization_documents',
      new TableForeignKey({
        name: 'fk_org_docs_organization_id',
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );
    await queryRunner.createForeignKey(
      'organization_documents',
      new TableForeignKey({
        name: 'fk_org_docs_category_id',
        columnNames: ['category_id'],
        referencedTableName: 'organization_document_categories',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
      }),
    );
    await queryRunner.createForeignKey(
      'organization_documents',
      new TableForeignKey({
        name: 'fk_org_docs_uploaded_by',
        columnNames: ['uploaded_by'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
      }),
    );

    await queryRunner.createIndex(
      'organization_documents',
      new TableIndex({ name: 'idx_org_docs_org', columnNames: ['organization_id'] }),
    );
    await queryRunner.createIndex(
      'organization_documents',
      new TableIndex({ name: 'idx_org_docs_cat', columnNames: ['category_id'] }),
    );
    await queryRunner.createIndex(
      'organization_documents',
      new TableIndex({ name: 'idx_org_docs_org_cat', columnNames: ['organization_id', 'category_id'] }),
    );

    await queryRunner.query(
      `CREATE INDEX idx_org_docs_expiry ON organization_documents (expiration_date) WHERE expiration_date IS NOT NULL`,
    );
    await queryRunner.query(
      `CREATE INDEX idx_org_docs_required ON organization_documents (organization_id, is_required) WHERE is_required = true`,
    );

    // Use double precision[] for embeddings so the migration runs without pgvector
    await queryRunner.query(`
      CREATE TABLE "organization_document_chunks" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "document_id" uuid NOT NULL,
        "organization_id" uuid NOT NULL,
        "chunk_index" integer NOT NULL,
        "chunk_text" text NOT NULL,
        "chunk_tokens" integer,
        "metadata" jsonb NOT NULL DEFAULT '{}',
        "embedding" double precision[],
        "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        CONSTRAINT "PK_2086d05c088a06b077ce5b42006" PRIMARY KEY ("id")
      )
    `);

    await queryRunner.createForeignKey(
      'organization_document_chunks',
      new TableForeignKey({
        name: 'fk_org_doc_chunks_document_id',
        columnNames: ['document_id'],
        referencedTableName: 'organization_documents',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );

    await queryRunner.createIndex(
      'organization_document_chunks',
      new TableIndex({ name: 'idx_org_doc_chunks_doc', columnNames: ['document_id'] }),
    );
    await queryRunner.createIndex(
      'organization_document_chunks',
      new TableIndex({ name: 'idx_org_doc_chunks_org', columnNames: ['organization_id'] }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex('organization_document_chunks', 'idx_org_doc_chunks_org');
    await queryRunner.dropIndex('organization_document_chunks', 'idx_org_doc_chunks_doc');
    await queryRunner.dropForeignKey('organization_document_chunks', 'fk_org_doc_chunks_document_id');
    await queryRunner.dropTable('organization_document_chunks', true);

    await queryRunner.query('DROP INDEX IF EXISTS idx_org_docs_required');
    await queryRunner.query('DROP INDEX IF EXISTS idx_org_docs_expiry');
    await queryRunner.dropIndex('organization_documents', 'idx_org_docs_org_cat');
    await queryRunner.dropIndex('organization_documents', 'idx_org_docs_cat');
    await queryRunner.dropIndex('organization_documents', 'idx_org_docs_org');
    await queryRunner.dropForeignKey('organization_documents', 'fk_org_docs_uploaded_by');
    await queryRunner.dropForeignKey('organization_documents', 'fk_org_docs_category_id');
    await queryRunner.dropForeignKey('organization_documents', 'fk_org_docs_organization_id');
    await queryRunner.dropTable('organization_documents', true);

    await queryRunner.dropIndex('organization_document_categories', 'idx_org_doc_cat_active');
    await queryRunner.dropIndex('organization_document_categories', 'idx_org_doc_cat_org');
    await queryRunner.dropForeignKey('organization_document_categories', 'fk_org_doc_cat_organization_id');
    await queryRunner.dropTable('organization_document_categories', true);
  }
}
