import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class CreateInserviceQuizQuestionsTable20260306120001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'inservice_quiz_questions',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'inservice_training_id',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'sort_order',
            type: 'integer',
            default: 0,
            isNullable: false,
          },
          {
            name: 'question_type',
            type: 'varchar',
            length: '30',
            isNullable: false,
          },
          {
            name: 'question_text',
            type: 'text',
            isNullable: false,
          },
          {
            name: 'options',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'correct_answer_index',
            type: 'integer',
            isNullable: true,
          },
          {
            name: 'correct_boolean',
            type: 'boolean',
            isNullable: true,
          },
          {
            name: 'correct_text',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'sample_answer',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'left_column',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'right_column',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'correct_matches',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'explanation',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
          {
            name: 'updated_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'inservice_quiz_questions',
      new TableForeignKey({
        columnNames: ['inservice_training_id'],
        referencedTableName: 'inservice_trainings',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_inservice_quiz_questions_inservice_training_id',
      }),
    );

    await queryRunner.createIndex(
      'inservice_quiz_questions',
      new TableIndex({
        name: 'idx_inservice_quiz_questions_inservice_training_id',
        columnNames: ['inservice_training_id'],
      }),
    );

    await queryRunner.createIndex(
      'inservice_quiz_questions',
      new TableIndex({
        name: 'idx_inservice_quiz_questions_inservice_training_id_sort_order',
        columnNames: ['inservice_training_id', 'sort_order'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'inservice_quiz_questions',
      'idx_inservice_quiz_questions_inservice_training_id_sort_order',
    );
    await queryRunner.dropIndex(
      'inservice_quiz_questions',
      'idx_inservice_quiz_questions_inservice_training_id',
    );
    await queryRunner.dropForeignKey(
      'inservice_quiz_questions',
      'fk_inservice_quiz_questions_inservice_training_id',
    );
    await queryRunner.dropTable('inservice_quiz_questions', true);
  }
}
