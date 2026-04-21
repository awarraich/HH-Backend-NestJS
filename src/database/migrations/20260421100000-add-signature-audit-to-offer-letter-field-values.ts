import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Adds `signature_audit` (nullable jsonb) to `offer_letter_field_values`.
 *
 * Used to record the ESIGN/UETA audit trail on signature and initials
 * fields — consent version, consent text, IP, user-agent, document hash
 * (sha256 of the template bytes), and a server-authoritative timestamp.
 * Nullable so legacy rows remain valid and so non-signature fields (text,
 * date, etc.) can keep writing without audit metadata.
 */
export class AddSignatureAuditToOfferLetterFieldValues20260421100000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'offer_letter_field_values',
      new TableColumn({
        name: 'signature_audit',
        type: 'jsonb',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn(
      'offer_letter_field_values',
      'signature_audit',
    );
  }
}
