import { MigrationInterface, QueryRunner } from 'typeorm';

export class DropSupervisorNameEmailFromAssignments20260330100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE competency_assignments DROP COLUMN IF EXISTS supervisor_name`);
    await queryRunner.query(`ALTER TABLE competency_assignments DROP COLUMN IF EXISTS supervisor_email`);
    await queryRunner.query(`ALTER TABLE competency_assignments DROP COLUMN IF EXISTS job_title`);
    await queryRunner.query(`ALTER TABLE competency_assignments DROP COLUMN IF EXISTS employee_id`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE competency_assignments ADD COLUMN supervisor_name VARCHAR(255) NOT NULL DEFAULT ''`);
    await queryRunner.query(`ALTER TABLE competency_assignments ADD COLUMN supervisor_email VARCHAR(255) NOT NULL DEFAULT ''`);
    await queryRunner.query(`ALTER TABLE competency_assignments ADD COLUMN job_title VARCHAR(255) NOT NULL DEFAULT ''`);
    await queryRunner.query(`ALTER TABLE competency_assignments ADD COLUMN employee_id UUID REFERENCES users(id)`);
  }
}
