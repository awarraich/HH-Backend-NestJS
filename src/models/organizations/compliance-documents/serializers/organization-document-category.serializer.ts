import { OrganizationDocumentCategory } from '../entities/organization-document-category.entity';

export class OrganizationDocumentCategorySerializer {
  serialize(category: OrganizationDocumentCategory, documentCount?: number) {
    return {
      id: category.id,
      organization_id: category.organization_id,
      name: category.name,
      description: category.description,
      icon: category.icon,
      color: category.color,
      sort_order: category.sort_order,
      is_active: category.is_active,
      is_default: category.is_default,
      document_count: documentCount ?? 0,
      created_at: category.created_at,
      updated_at: category.updated_at,
    };
  }

  serializeMany(categories: OrganizationDocumentCategory[], countMap?: Map<string, number>) {
    return categories.map((c) => this.serialize(c, countMap?.get(c.id) ?? 0));
  }
}
