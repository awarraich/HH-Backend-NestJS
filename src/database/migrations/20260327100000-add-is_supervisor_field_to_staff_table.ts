import { Migration, MigrationInterface, QueryRunner } from "typeorm";


export class AddIsSupervisorFieldToStaffTable20260327100000 implements MigrationInterface {
    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE organization_staff ADD COLUMN is_supervisor boolean NOT NULL DEFAULT false`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE organization_staff DROP COLUMN is_supervisor`);
    }

}