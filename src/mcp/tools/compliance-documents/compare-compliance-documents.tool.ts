import { z } from 'zod';
import type { OrganizationDocumentsChatService } from '../../../models/organizations/compliance-documents/services/organization-documents-chat.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  document_ids: z
    .array(z.string().uuid())
    .min(2)
    .max(5)
    .describe('Array of 2-5 document UUIDs to compare'),
  comparison_focus: z
    .string()
    .optional()
    .describe('Aspect to focus on (e.g. "coverage limits", "expiration dates")'),
};

export const compareComplianceDocumentsTool = {
  name: TOOL_NAMES.COMPARE_COMPLIANCE_DOCUMENTS,
  description:
    "Compare 2-5 compliance documents side by side. Use for 'compare these policies', 'what changed?', or 'which insurance has better coverage?'.",
  inputSchema,
};

export function createCompareComplianceDocumentsHandler(
  chatService: OrganizationDocumentsChatService,
  organizationId: string,
) {
  return async (args: { document_ids: string[]; comparison_focus?: string }) => {
    const result = await chatService.compareDocuments(
      organizationId,
      args.document_ids,
      args.comparison_focus,
    );
    return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
  };
}
