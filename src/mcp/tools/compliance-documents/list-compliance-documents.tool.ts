import { z } from 'zod';
import type { OrganizationDocumentsService } from '../../../models/organizations/compliance-documents/services/organization-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  category_id: z.string().uuid().optional().describe('Filter by category UUID'),
  status: z
    .enum(['valid', 'expired', 'expiring_soon', 'missing'])
    .optional()
    .describe('Filter by document status'),
  limit: z.number().int().min(1).max(100).optional().describe('Max results (default 50)'),
};

export const listComplianceDocumentsTool = {
  name: TOOL_NAMES.LIST_COMPLIANCE_DOCUMENTS,
  description:
    "List all compliance documents for this organization. Returns document name, category, status, expiration date, and file info. Use when asked 'what documents do we have?', 'show expired documents', or 'list insurance documents'.",
  inputSchema,
};

export function createListComplianceDocumentsHandler(
  service: OrganizationDocumentsService,
  organizationId: string,
) {
  return async (args: { category_id?: string; status?: string; limit?: number }) => {
    const result = await service.findAll(organizationId, {
      category_id: args.category_id,
      status: args.status,
      limit: args.limit ?? 50,
      page: 1,
    });
    return { content: [{ type: 'text' as const, text: JSON.stringify(result.data, null, 2) }] };
  };
}
