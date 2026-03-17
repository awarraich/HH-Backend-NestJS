import { z } from 'zod';
import type { OrganizationDocumentsChatService } from '../../../models/organizations/compliance-documents/services/organization-documents-chat.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  message: z
    .string()
    .describe("Question about compliance documents (e.g. 'When does our CLIA expire?')"),
  document_ids: z
    .array(z.string().uuid())
    .optional()
    .describe('Optional: restrict to specific document IDs'),
};

export const chatWithComplianceDocumentsTool = {
  name: TOOL_NAMES.CHAT_WITH_COMPLIANCE_DOCUMENTS,
  description:
    'Ask any question about compliance document content. Uses vector search + LLM to generate answers with source citations. Use for summarizing, answering questions, or extracting details.',
  inputSchema,
};

export function createChatWithComplianceDocumentsHandler(
  chatService: OrganizationDocumentsChatService,
  organizationId: string,
) {
  return async (args: { message: string; document_ids?: string[] }) => {
    const result = await chatService.chat(
      organizationId,
      args.message,
      undefined,
      args.document_ids,
    );
    return { content: [{ type: 'text' as const, text: JSON.stringify(result) }] };
  };
}
