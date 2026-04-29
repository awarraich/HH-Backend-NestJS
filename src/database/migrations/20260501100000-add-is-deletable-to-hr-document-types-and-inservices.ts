import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddIsDeletableToHrDocumentTypesAndInservices20260501100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'hr_document_types',
      new TableColumn({
        name: 'is_deletable',
        type: 'boolean',
        default: true,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'inservice_trainings',
      new TableColumn({
        name: 'is_deletable',
        type: 'boolean',
        default: true,
        isNullable: false,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('inservice_trainings', 'is_deletable');
    await queryRunner.dropColumn('hr_document_types', 'is_deletable');
  }
}
