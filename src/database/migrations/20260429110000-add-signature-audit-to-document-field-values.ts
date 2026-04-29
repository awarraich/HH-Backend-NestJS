import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Add a `signature_audit` JSONB column to `document_field_values` so the
 * legacy competency / external-document signing flow (driven by
 * SupervisorDocumentFiller, PdfDocumentFiller, etc.) can persist the same
 * audit metadata the offer-letter path already does:
 *
 *   {
 *     consentVersion?: string,
 *     consentText?: string,
 *     ip?: string | null,
 *     userAgent?: string | null,
 *     signedAt: string,                    // ISO timestamp
 *     signerName: string | null,           // snapshotted at sign time
 *     signerTitle: string | null,          // snapshotted at sign time
 *     geolocation: {                       // null when user denied / unsupported
 *       latitude: number,
 *       longitude: number,
 *       accuracy: number | null,
 *       capturedAt: string | null
 *     } | null
 *   }
 *
 * Nullable; existing legacy rows stay null and the SignedDocumentInfo
 * block falls back to "Not captured" / em-dash for those signatures so
 * they keep rendering without a backfill.
 */
export class AddSignatureAuditToDocumentFieldValues20260429110000
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'document_field_values',
      new TableColumn({
        name: 'signature_audit',
        type: 'jsonb',
        isNullable: true,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('document_field_values', 'signature_audit');
  }
}
