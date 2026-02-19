import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Seeds the organization_types table with the six healthcare organization
 * categories. The table itself is created by 20260208000000.
 *
 * The GET /v1/api/organization-types endpoint and the frontend
 * OrganizationProfileStep rely on these rows existing.
 */
export class SeedOrganizationTypesTable20260219100001
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    const types = [
      { id: 1, name: 'HOME HEALTH' },
      { id: 2, name: 'HOSPICE' },
      { id: 3, name: 'NURSING HOME' },
      { id: 4, name: 'BOARD AND CARE' },
      { id: 5, name: 'PHARMACIST' },
      { id: 6, name: 'LAB' },
    ];

    for (const type of types) {
      const exists = await queryRunner.query(
        `SELECT 1 FROM organization_types WHERE id = $1 OR name = $2 LIMIT 1`,
        [type.id, type.name],
      );

      if (exists.length === 0) {
        await queryRunner.query(
          `INSERT INTO organization_types (id, name) VALUES ($1, $2)`,
          [type.id, type.name],
        );
      }
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `DELETE FROM organization_types WHERE name IN ('HOME HEALTH', 'HOSPICE', 'NURSING HOME', 'BOARD AND CARE', 'PHARMACIST', 'LAB')`,
    );
  }
}
