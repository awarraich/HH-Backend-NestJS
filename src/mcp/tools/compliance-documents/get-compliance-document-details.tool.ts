import { z } from 'zod';
import type { OrganizationDocumentsService } from '../../../models/organizations/compliance-documents/services/organization-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  document_id: z.string().uuid().describe('UUID of the compliance document'),
};

export const getComplianceDocumentDetailsTool = {
  name: TOOL_NAMES.GET_COMPLIANCE_DOCUMENT_DETAILS,
  description:
    "Get full details of a specific compliance document including metadata, status, expiration, and extracted text. Use when asked about a specific document's details or content.",
  inputSchema,
};

export function createGetComplianceDocumentDetailsHandler(
  service: OrganizationDocumentsService,
  organizationId: string,
) {
  return async (args: { document_id: string }) => {
    const result = await service.getDocumentDetails(organizationId, args.document_id);
    return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
  };
}
