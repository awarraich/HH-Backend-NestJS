import { z } from 'zod';
import type { OrganizationDocumentsService } from '../../../models/organizations/compliance-documents/services/organization-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  query: z
    .string()
    .describe('Natural language search query (e.g. "infection control policy", "liability coverage")'),
  category_id: z.string().uuid().optional().describe('Restrict search to a specific category'),
  limit: z.number().int().min(1).max(20).optional().describe('Max results (default 10)'),
};

export const searchComplianceDocumentsTool = {
  name: TOOL_NAMES.SEARCH_COMPLIANCE_DOCUMENTS,
  description:
    'Semantic search across all compliance document content using vector embeddings. Finds relevant passages even without exact keyword matches. Use for questions about document content.',
  inputSchema,
};

export function createSearchComplianceDocumentsHandler(
  service: OrganizationDocumentsService,
  organizationId: string,
) {
  return async (args: { query: string; category_id?: string; limit?: number }) => {
    const result = await service.semanticSearch(
      organizationId,
      args.query,
      args.category_id,
      args.limit,
    );
    return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
  };
}
