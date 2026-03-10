import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddMedicationEmbedding20260223100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('CREATE EXTENSION IF NOT EXISTS vector');
    await queryRunner.query(
      'ALTER TABLE patient_medications ADD COLUMN IF NOT EXISTS embedding vector(1536) NULL',
    );
    await queryRunner.query(
      'CREATE INDEX IF NOT EXISTS idx_patient_medications_embedding ON patient_medications USING hnsw (embedding vector_cosine_ops)',
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query('DROP INDEX IF EXISTS idx_patient_medications_embedding');
    await queryRunner.query('ALTER TABLE patient_medications DROP COLUMN IF EXISTS embedding');
  }
}
