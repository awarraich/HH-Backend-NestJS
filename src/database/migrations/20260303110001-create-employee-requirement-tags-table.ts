import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableIndex,
  TableUnique,
} from 'typeorm';

export class CreateEmployeeRequirementTagsTable20260303110001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'employee_requirement_tags',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          { name: 'employee_id', type: 'uuid', isNullable: false },
          { name: 'requirement_tag_id', type: 'uuid', isNullable: false },
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
      'employee_requirement_tags',
      new TableUnique({
        name: 'uq_employee_requirement_tags_employee_tag',
        columnNames: ['employee_id', 'requirement_tag_id'],
      }),
    );

    await queryRunner.createForeignKey(
      'employee_requirement_tags',
      new TableForeignKey({
        columnNames: ['employee_id'],
        referencedTableName: 'employees',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_requirement_tags_employee_id',
      }),
    );

    await queryRunner.createForeignKey(
      'employee_requirement_tags',
      new TableForeignKey({
        columnNames: ['requirement_tag_id'],
        referencedTableName: 'requirement_tags',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_employee_requirement_tags_requirement_tag_id',
      }),
    );

    await queryRunner.createIndex(
      'employee_requirement_tags',
      new TableIndex({
        name: 'idx_employee_requirement_tags_employee_id',
        columnNames: ['employee_id'],
      }),
    );

    await queryRunner.createIndex(
      'employee_requirement_tags',
      new TableIndex({
        name: 'idx_employee_requirement_tags_requirement_tag_id',
        columnNames: ['requirement_tag_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropIndex(
      'employee_requirement_tags',
      'idx_employee_requirement_tags_requirement_tag_id',
    );
    await queryRunner.dropIndex(
      'employee_requirement_tags',
      'idx_employee_requirement_tags_employee_id',
    );
    await queryRunner.dropForeignKey(
      'employee_requirement_tags',
      'fk_employee_requirement_tags_requirement_tag_id',
    );
    await queryRunner.dropForeignKey(
      'employee_requirement_tags',
      'fk_employee_requirement_tags_employee_id',
    );
    await queryRunner.dropTable('employee_requirement_tags', true);
  }
}
