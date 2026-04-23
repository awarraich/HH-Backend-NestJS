import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddTitlesToInserviceTrainings20260422100000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'inservice_trainings',
      new TableColumn({
        name: 'video_titles',
        type: 'jsonb',
        default: "'[]'::jsonb",
        isNullable: false,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('inservice_trainings', 'video_titles');
  }
}
