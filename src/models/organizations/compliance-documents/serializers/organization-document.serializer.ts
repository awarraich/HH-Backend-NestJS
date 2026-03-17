import { OrganizationDocument } from '../entities/organization-document.entity';

export type DocumentStatus = 'valid' | 'expired' | 'expiring_soon' | 'no_expiration';

export function computeDocumentStatus(doc: OrganizationDocument): DocumentStatus {
  if (!doc.has_expiration || !doc.expiration_date) return 'no_expiration';
  const now = new Date();
  const expDate = new Date(doc.expiration_date);
  if (expDate < now) return 'expired';
  const daysUntil = (expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
  if (daysUntil <= (doc.expiration_reminder_days ?? 90)) return 'expiring_soon';
  return 'valid';
}

export function computeDaysUntilExpiration(doc: OrganizationDocument): number | null {
  if (!doc.has_expiration || !doc.expiration_date) return null;
  const now = new Date();
  const expDate = new Date(doc.expiration_date);
  return Math.floor((expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

export class OrganizationDocumentSerializer {
  serialize(doc: OrganizationDocument) {
    const status = computeDocumentStatus(doc);
    const daysUntilExpiration = computeDaysUntilExpiration(doc);

    return {
      id: doc.id,
      organization_id: doc.organization_id,
      document_name: doc.document_name,
      file_name: doc.file_name,
      file_size_bytes: doc.file_size_bytes ? Number(doc.file_size_bytes) : null,
      mime_type: doc.mime_type,
      is_required: doc.is_required,
      has_expiration: doc.has_expiration,
      expiration_date: doc.expiration_date,
      expiration_reminder_days: doc.expiration_reminder_days,
      status,
      days_until_expiration: daysUntilExpiration,
      extraction_status: doc.extraction_status,
      created_at: doc.created_at,
      updated_at: doc.updated_at,
      category: doc.category
        ? {
            id: doc.category.id,
            name: doc.category.name,
            icon: doc.category.icon,
            color: doc.category.color,
          }
        : null,
      uploaded_by: doc.uploadedByUser
        ? {
            id: doc.uploadedByUser.id,
            name: `${doc.uploadedByUser.firstName ?? ''} ${doc.uploadedByUser.lastName ?? ''}`.trim(),
          }
        : null,
    };
  }

  serializeMany(docs: OrganizationDocument[]) {
    return docs.map((d) => this.serialize(d));
  }
}
