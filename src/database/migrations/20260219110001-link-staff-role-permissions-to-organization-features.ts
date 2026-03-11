import {
  MigrationInterface,
  QueryRunner,
  TableColumn,
  TableForeignKey,
  TableUnique,
  TableIndex,
} from 'typeorm';

export class LinkStaffRolePermissionsToOrganizationFeatures20260219110001 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'organization_staff_role_permissions',
      new TableColumn({
        name: 'feature_id',
        type: 'uuid',
        isNullable: true,
      }),
    );

    await queryRunner.createForeignKey(
      'organization_staff_role_permissions',
      new TableForeignKey({
        columnNames: ['feature_id'],
        referencedTableName: 'organization_features',
        referencedColumnNames: ['id'],
        onDelete: 'RESTRICT',
        name: 'fk_org_staff_role_permissions_feature_id',
      }),
    );

    await queryRunner.query(`
      UPDATE organization_staff_role_permissions p
      SET feature_id = f.id
      FROM organization_features f
      WHERE f.code = p.feature
    `);

    await queryRunner.query(`
      DELETE FROM organization_staff_role_permissions WHERE feature_id IS NULL
    `);

    await queryRunner.changeColumn(
      'organization_staff_role_permissions',
      'feature_id',
      new TableColumn({
        name: 'feature_id',
        type: 'uuid',
        isNullable: false,
      }),
    );

    await queryRunner.dropUniqueConstraint(
      'organization_staff_role_permissions',
      'uq_org_staff_role_permissions_org_role_feature',
    );

    await queryRunner.dropIndex(
      'organization_staff_role_permissions',
      'idx_org_staff_role_permissions_feature',
    );

    await queryRunner.dropColumn('organization_staff_role_permissions', 'feature');

    await queryRunner.createUniqueConstraint(
      'organization_staff_role_permissions',
      new TableUnique({
        name: 'uq_org_staff_role_permissions_org_role_feature_id',
        columnNames: ['organization_id', 'staff_role_id', 'feature_id'],
      }),
    );

    await queryRunner.createIndex(
      'organization_staff_role_permissions',
      new TableIndex({
        name: 'idx_org_staff_role_permissions_feature_id',
        columnNames: ['feature_id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'organization_staff_role_permissions',
      new TableColumn({
        name: 'feature',
        type: 'varchar',
        length: '100',
        isNullable: true,
      }),
    );

    await queryRunner.query(`
      UPDATE organization_staff_role_permissions p
      SET feature = f.code
      FROM organization_features f
      WHERE f.id = p.feature_id
    `);

    await queryRunner.changeColumn(
      'organization_staff_role_permissions',
      'feature',
      new TableColumn({
        name: 'feature',
        type: 'varchar',
        length: '100',
        isNullable: false,
      }),
    );

    await queryRunner.dropUniqueConstraint(
      'organization_staff_role_permissions',
      'uq_org_staff_role_permissions_org_role_feature_id',
    );

    await queryRunner.dropIndex(
      'organization_staff_role_permissions',
      'idx_org_staff_role_permissions_feature_id',
    );

    await queryRunner.dropForeignKey(
      'organization_staff_role_permissions',
      'fk_org_staff_role_permissions_feature_id',
    );

    await queryRunner.dropColumn('organization_staff_role_permissions', 'feature_id');

    await queryRunner.createUniqueConstraint(
      'organization_staff_role_permissions',
      new TableUnique({
        name: 'uq_org_staff_role_permissions_org_role_feature',
        columnNames: ['organization_id', 'staff_role_id', 'feature'],
      }),
    );

    await queryRunner.createIndex(
      'organization_staff_role_permissions',
      new TableIndex({
        name: 'idx_org_staff_role_permissions_feature',
        columnNames: ['feature'],
      }),
    );
  }
}
