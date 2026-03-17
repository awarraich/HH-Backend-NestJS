import { MigrationInterface, QueryRunner } from 'typeorm';

export class SplitAddressIntoStructuredFields20260319400000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE employee_profiles ADD COLUMN address_line_1 varchar(255)`,
    );
    await queryRunner.query(
      `ALTER TABLE employee_profiles ADD COLUMN address_line_2 varchar(255)`,
    );
    await queryRunner.query(
      `ALTER TABLE employee_profiles ADD COLUMN city varchar(100)`,
    );
    await queryRunner.query(
      `ALTER TABLE employee_profiles ADD COLUMN state varchar(100)`,
    );

    await queryRunner.query(
      `UPDATE employee_profiles SET address_line_1 = address WHERE address IS NOT NULL`,
    );

    await queryRunner.query(`ALTER TABLE employee_profiles DROP COLUMN address`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE employee_profiles ADD COLUMN address text`);

    await queryRunner.query(
      `UPDATE employee_profiles
       SET address = CONCAT_WS(', ', address_line_1, address_line_2, city, state)
       WHERE address_line_1 IS NOT NULL OR city IS NOT NULL OR state IS NOT NULL`,
    );

    await queryRunner.query(`ALTER TABLE employee_profiles DROP COLUMN address_line_1`);
    await queryRunner.query(`ALTER TABLE employee_profiles DROP COLUMN address_line_2`);
    await queryRunner.query(`ALTER TABLE employee_profiles DROP COLUMN city`);
    await queryRunner.query(`ALTER TABLE employee_profiles DROP COLUMN state`);
  }
}
