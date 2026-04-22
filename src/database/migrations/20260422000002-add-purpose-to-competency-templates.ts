import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Adds `purpose` column to `competency_templates` so the Document Workflow
 * page can split its list into two tabs — Document Templates (the original
 * use case) and Job Application Forms — without them bleeding into each
 * other. Default `'document'` keeps every existing row on the original tab.
 *
 * Values: `'document'` | `'applicant_form'`.
 */
export class AddPurposeToCompetencyTemplates20260422000002
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('competency_templates');
    if (!table) return;
    if (table.columns.some((c) => c.name === 'purpose')) return;

    await queryRunner.addColumn(
      'competency_templates',
      new TableColumn({
        name: 'purpose',
        type: 'varchar',
        length: '32',
        isNullable: false,
        default: "'document'",
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('competency_templates');
    if (!table) return;
    if (!table.columns.some((c) => c.name === 'purpose')) return;
    await queryRunner.dropColumn('competency_templates', 'purpose');
  }
}
