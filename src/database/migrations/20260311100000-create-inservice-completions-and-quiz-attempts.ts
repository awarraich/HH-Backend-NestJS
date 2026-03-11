import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
  TableUnique,
} from 'typeorm';

export class CreateInserviceCompletionsAndQuizAttempts20260311100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'inservice_completions',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          { name: 'inservice_training_id', type: 'uuid', isNullable: false },
          {
            name: 'progress_percent',
            type: 'integer',
            default: 0,
            isNullable: false,
          },
          {
            name: 'completed_at',
            type: 'timestamp with time zone',
            isNullable: true,
          },
          {
            name: 'expiration_at',
            type: 'timestamp with time zone',
            isNullable: true,
          },
          {
            name: 'last_quiz_score_percent',
            type: 'integer',
            isNullable: true,
          },
          {
            name: 'quiz_attempts_count',
            type: 'integer',
            default: 0,
            isNullable: false,
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

    await queryRunner.createUniqueConstraint(
      'inservice_completions',
      new TableUnique({
        name: 'uq_inservice_completions_employee_training',
        columnNames: ['employee_id', 'inservice_training_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'inservice_completions',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_inservice_completions_employee_id',
      }),
    );

    await queryRunner.createForeignKey(
      'inservice_completions',
      new TableForeignKey({
        columnNames: ['inservice_training_id'],
        referencedTableName: 'inservice_trainings',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_inservice_completions_inservice_training_id',
      }),
    );

    await queryRunner.createIndex(
      'inservice_completions',
      new TableIndex({
        name: 'idx_inservice_completions_employee_id',
        columnNames: ['employee_id'],
      }),
    );

    await queryRunner.createIndex(
      'inservice_completions',
      new TableIndex({
        name: 'idx_inservice_completions_inservice_training_id',
        columnNames: ['inservice_training_id'],
      }),
    );

    await queryRunner.createTable(
      new Table({
        name: 'inservice_quiz_attempts',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          { name: 'inservice_training_id', type: 'uuid', isNullable: false },
          {
            name: 'score_percent',
            type: 'integer',
            isNullable: false,
          },
          {
            name: 'passed',
            type: 'boolean',
            isNullable: false,
          },
          {
            name: 'created_at',
            type: 'timestamp with time zone',
            default: 'NOW()',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'inservice_quiz_attempts',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_inservice_quiz_attempts_employee_id',
      }),
    );

    await queryRunner.createForeignKey(
      'inservice_quiz_attempts',
      new TableForeignKey({
        columnNames: ['inservice_training_id'],
        referencedTableName: 'inservice_trainings',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_inservice_quiz_attempts_inservice_training_id',
      }),
    );

    await queryRunner.createIndex(
      'inservice_quiz_attempts',
      new TableIndex({
        name: 'idx_inservice_quiz_attempts_employee_id',
        columnNames: ['employee_id'],
      }),
    );

    await queryRunner.createIndex(
      'inservice_quiz_attempts',
      new TableIndex({
        name: 'idx_inservice_quiz_attempts_inservice_training_id',
        columnNames: ['inservice_training_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'inservice_quiz_attempts',
      'idx_inservice_quiz_attempts_inservice_training_id',
    );
    await queryRunner.dropIndex(
      'inservice_quiz_attempts',
      'idx_inservice_quiz_attempts_employee_id',
    );
    await queryRunner.dropForeignKey(
      'inservice_quiz_attempts',
      'fk_inservice_quiz_attempts_inservice_training_id',
    );
    await queryRunner.dropForeignKey(
      'inservice_quiz_attempts',
      'fk_inservice_quiz_attempts_employee_id',
    );
    await queryRunner.dropTable('inservice_quiz_attempts', true);

    await queryRunner.dropIndex(
      'inservice_completions',
      'idx_inservice_completions_inservice_training_id',
    );
    await queryRunner.dropIndex(
      'inservice_completions',
      'idx_inservice_completions_employee_id',
    );
    await queryRunner.dropForeignKey(
      'inservice_completions',
      'fk_inservice_completions_inservice_training_id',
    );
    await queryRunner.dropForeignKey(
      'inservice_completions',
      'fk_inservice_completions_employee_id',
    );
    await queryRunner.dropTable('inservice_completions', true);
  }
}
