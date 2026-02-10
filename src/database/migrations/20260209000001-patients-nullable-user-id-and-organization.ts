import { MigrationInterface, QueryRunner, TableColumn, TableForeignKey } from 'typeorm';

export class PatientsNullableUserIdAndOrganization20260209000001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "patients" DROP CONSTRAINT IF EXISTS "patients_user_id_key"`
    );
    await queryRunner.changeColumn(
      'patients',
      'user_id',
      new TableColumn({
        name: 'user_id',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.query(
      `CREATE UNIQUE INDEX "idx_patients_user_id_unique" ON "patients" ("user_id") WHERE "user_id" IS NOT NULL`
    );

    await queryRunner.addColumn(
      'patients',
      new TableColumn({
        name: 'organization_id',
        type: 'uuid',
        isNullable: true,
      }),
    );
    await queryRunner.createForeignKey(
      'patients',
      new TableForeignKey({
        columnNames: ['organization_id'],
        referencedTableName: 'organizations',
        referencedColumnNames: ['id'],
        onDelete: 'SET NULL',
        name: 'fk_patients_organization_id',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropForeignKey('patients', 'fk_patients_organization_id');
    await queryRunner.dropColumn('patients', 'organization_id');
    await queryRunner.dropIndex('patients', 'idx_patients_user_id_unique');
    await queryRunner.changeColumn(
      'patients',
      'user_id',
      new TableColumn({
        name: 'user_id',
        type: 'uuid',
        isNullable: false,
      }),
    );
    await queryRunner.query(
      `ALTER TABLE "patients" ADD CONSTRAINT "patients_user_id_key" UNIQUE ("user_id")`
    );
  }
}
