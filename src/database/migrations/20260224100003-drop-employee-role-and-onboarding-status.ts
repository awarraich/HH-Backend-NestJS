import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class DropEmployeeRoleAndOnboardingStatus20260224100003 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('employees', 'role');
    await queryRunner.dropColumn('employee_profiles', 'onboarding_status');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'employees',
      new TableColumn({
        name: 'role',
        type: 'varchar',
        length: '20',
        isNullable: true,
      }),
    );
    await queryRunner.addColumn(
      'employee_profiles',
      new TableColumn({
        name: 'onboarding_status',
        type: 'varchar',
        length: '10',
        isNullable: false,
        default: "'pending'",
      }),
    );
  }
}
