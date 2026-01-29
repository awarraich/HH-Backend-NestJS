import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateCreditPackagesTable20260129055907 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'credit_packages',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'name',
            type: 'varchar',
            length: '100',
            isNullable: false,
          },
          {
            name: 'credits',
            type: 'integer',
            isNullable: false,
          },
          {
            name: 'price_usd',
            type: 'numeric',
            precision: 10,
            scale: 2,
            isNullable: false,
          },
          {
            name: 'stripe_price_id',
            type: 'varchar',
            length: '100',
            isNullable: false,
          },
          {
            name: 'is_active',
            type: 'boolean',
            default: true,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );

    // Add check constraints
    await queryRunner.query(`
      ALTER TABLE "credit_packages"
      ADD CONSTRAINT "chk_credit_packages_credits_positive"
      CHECK (credits > 0)
    `);

    await queryRunner.query(`
      ALTER TABLE "credit_packages"
      ADD CONSTRAINT "chk_credit_packages_price_positive"
      CHECK (price_usd > 0)
    `);

    // Create unique index for stripe_price_id
    await queryRunner.createIndex(
      'credit_packages',
      new TableIndex({
        name: 'idx_credit_packages_stripe_price_id',
        columnNames: ['stripe_price_id'],
        isUnique: true,
      }),
    );

    // Create index for is_active
    await queryRunner.createIndex(
      'credit_packages',
      new TableIndex({
        name: 'idx_credit_packages_is_active',
        columnNames: ['is_active'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop indexes
    await queryRunner.dropIndex('credit_packages', 'idx_credit_packages_is_active');
    await queryRunner.dropIndex('credit_packages', 'idx_credit_packages_stripe_price_id');

    // Drop check constraints
    await queryRunner.query(`
      ALTER TABLE "credit_packages"
      DROP CONSTRAINT IF EXISTS "chk_credit_packages_price_positive"
    `);

    await queryRunner.query(`
      ALTER TABLE "credit_packages"
      DROP CONSTRAINT IF EXISTS "chk_credit_packages_credits_positive"
    `);

    // Drop table
    await queryRunner.dropTable('credit_packages');
  }
}

