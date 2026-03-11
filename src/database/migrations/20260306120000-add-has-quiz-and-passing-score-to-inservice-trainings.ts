import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddHasQuizAndPassingScoreToInserviceTrainings20260306120000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'inservice_trainings',
      new TableColumn({
        name: 'has_quiz',
        type: 'boolean',
        default: false,
        isNullable: false,
      }),
    );
    await queryRunner.addColumn(
      'inservice_trainings',
      new TableColumn({
        name: 'passing_score_percent',
        type: 'integer',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('inservice_trainings', 'passing_score_percent');
    await queryRunner.dropColumn('inservice_trainings', 'has_quiz');
  }
}
