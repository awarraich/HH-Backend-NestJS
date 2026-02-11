import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class CreateReferralDocumentsTable20260210000003 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'referral_documents',
        columns: [
          { name: 'id', type: 'uuid', isPrimary: true, default: 'gen_random_uuid()' },
          { name: 'referral_id', type: 'uuid', isNullable: false },
          { name: 'file_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'file_url', type: 'varchar', length: '2048', isNullable: false },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createForeignKey(
      'referral_documents',
      new TableForeignKey({
        columnNames: ['referral_id'],
        referencedTableName: 'referrals',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        name: 'fk_referral_documents_referral_id',
      }),
    );

    await queryRunner.createIndex(
      'referral_documents',
      new TableIndex({ name: 'idx_referral_documents_referral_id', columnNames: ['referral_id'] }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('referral_documents', true);
  }
}
