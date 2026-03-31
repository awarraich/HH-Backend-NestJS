import { MigrationInterface, QueryRunner } from 'typeorm';

export class RemoveGridTemplateColumns20260331100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS idx_ct_mode`);
    await queryRunner.query(`ALTER TABLE competency_templates DROP CONSTRAINT IF EXISTS competency_templates_mode_check`);
    await queryRunner.query(`ALTER TABLE competency_templates DROP COLUMN IF EXISTS mode`);
    await queryRunner.query(`ALTER TABLE competency_templates DROP COLUMN IF EXISTS layout`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE competency_templates ADD COLUMN layout JSONB NOT NULL DEFAULT '{"rows":1,"cols":1,"cells":[[]]}'`);
    await queryRunner.query(`ALTER TABLE competency_templates ADD COLUMN mode VARCHAR(20) NOT NULL DEFAULT 'document' CHECK (mode IN ('grid', 'document'))`);
    await queryRunner.query(`CREATE INDEX idx_ct_mode ON competency_templates(organization_id, mode)`);
  }
}
