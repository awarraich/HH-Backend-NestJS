import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableIndex,
  TableForeignKey,
} from 'typeorm';

export class CreateOfferLetterSigningTokensTable20260415100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    if (await queryRunner.getTable('offer_letter_signing_tokens')) {
      return;
    }
    await queryRunner.createTable(
      new Table({
        name: 'offer_letter_signing_tokens',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'uuid_generate_v4()',
          },
          { name: 'token', type: 'varchar', length: '128', isNullable: false, isUnique: true },
          { name: 'job_application_id', type: 'uuid', isNullable: false },
          { name: 'candidate_email', type: 'varchar', length: '255', isNullable: false },
          { name: 'candidate_name', type: 'varchar', length: '255', isNullable: false },
          { name: 'job_title', type: 'varchar', length: '500', isNullable: false },
          { name: 'organization_id', type: 'uuid', isNullable: false },
          { name: 'pdf_url', type: 'varchar', length: '2048', isNullable: false },
          { name: 'signature_position', type: 'jsonb', isNullable: true },
          { name: 'expires_at', type: 'timestamp', isNullable: false },
          { name: 'used_at', type: 'timestamp', isNullable: true },
          { name: 'signed_pdf_url', type: 'varchar', length: '2048', isNullable: true },
          { name: 'audit_trail', type: 'jsonb', isNullable: true },
          { name: 'created_at', type: 'timestamp', default: 'CURRENT_TIMESTAMP' },
        ],
      }),
      true,
    );

    await queryRunner.createIndex(
      'offer_letter_signing_tokens',
      new TableIndex({
        name: 'IDX_offer_letter_signing_tokens_token',
        columnNames: ['token'],
        isUnique: true,
      }),
    );
    await queryRunner.createIndex(
      'offer_letter_signing_tokens',
      new TableIndex({
        name: 'IDX_offer_letter_signing_tokens_expires_at',
        columnNames: ['expires_at'],
      }),
    );
    await queryRunner.createForeignKey(
      'offer_letter_signing_tokens',
      new TableForeignKey({
        columnNames: ['job_application_id'],
        referencedTableName: 'job_applications',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    const table = await queryRunner.getTable('offer_letter_signing_tokens');
    if (table) {
      const fk = table.foreignKeys.find(
        (fk) => fk.columnNames.indexOf('job_application_id') !== -1,
      );
      if (fk) await queryRunner.dropForeignKey('offer_letter_signing_tokens', fk);
      await queryRunner.dropTable('offer_letter_signing_tokens');
    }
  }
}
