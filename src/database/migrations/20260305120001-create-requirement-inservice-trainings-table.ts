import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

export class CreateRequirementInserviceTrainingsTable20260305120001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'requirement_inservice_trainings',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'requirement_tag_id',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'inservice_training_id',
            type: 'uuid',
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

    await queryRunner.createUniqueConstraint(
      'requirement_inservice_trainings',
      new TableUnique({
        name: 'uq_requirement_inservice_trainings_tag_inservice',
        columnNames: ['requirement_tag_id', 'inservice_training_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'requirement_inservice_trainings',
      new TableForeignKey({
        columnNames: ['requirement_tag_id'],
        referencedTableName: 'requirement_tags',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_requirement_inservice_trainings_requirement_tag_id',
      }),
    );

    await queryRunner.createForeignKey(
      'requirement_inservice_trainings',
      new TableForeignKey({
        columnNames: ['inservice_training_id'],
        referencedTableName: 'inservice_trainings',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_requirement_inservice_trainings_inservice_training_id',
      }),
    );

    await queryRunner.createIndex(
      'requirement_inservice_trainings',
      new TableIndex({
        name: 'idx_requirement_inservice_trainings_requirement_tag_id',
        columnNames: ['requirement_tag_id'],
      }),
    );

    await queryRunner.createIndex(
      'requirement_inservice_trainings',
      new TableIndex({
        name: 'idx_requirement_inservice_trainings_inservice_training_id',
        columnNames: ['inservice_training_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'requirement_inservice_trainings',
      'idx_requirement_inservice_trainings_inservice_training_id',
    );
    await queryRunner.dropIndex(
      'requirement_inservice_trainings',
      'idx_requirement_inservice_trainings_requirement_tag_id',
    );
    await queryRunner.dropForeignKey(
      'requirement_inservice_trainings',
      'fk_requirement_inservice_trainings_inservice_training_id',
    );
    await queryRunner.dropForeignKey(
      'requirement_inservice_trainings',
      'fk_requirement_inservice_trainings_requirement_tag_id',
    );
    await queryRunner.dropTable('requirement_inservice_trainings', true);
  }
}
