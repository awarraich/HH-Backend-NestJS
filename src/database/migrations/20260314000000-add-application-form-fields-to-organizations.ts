import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Add application_form_fields (JSONB) to organizations for job application form config.
 * Stores array of { id, label, type, required, placeholder?, options? }.
 */
export class AddApplicationFormFieldsToOrganizations20260314000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('organizations');
    if (table && !table.findColumnByName('application_form_fields')) {
      await queryRunner.addColumn(
        'organizations',
        new TableColumn({
          name: 'application_form_fields',
          type: 'jsonb',
          isNullable: true,
        }),
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('organizations');
    if (table?.findColumnByName('application_form_fields')) {
      await queryRunner.dropColumn('organizations', 'application_form_fields');
    }
  }
}
