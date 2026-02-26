import { z } from 'zod';
import type { EmployeeDocumentsService } from '../../../models/organizations/hr-files-setup/services/employee-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const chatWithEmployeeDocumentsInputSchema = {
  message: z
    .string()
    .describe(
      "The user's question or message (e.g. 'Summarize these documents')",
    ),
  document_ids: z
    .array(z.string().uuid())
    .optional()
    .describe('Optional: restrict to these document IDs'),
};

export const chatWithEmployeeDocumentsTool = {
  name: TOOL_NAMES.CHAT_WITH_EMPLOYEE_DOCUMENTS,
  description:
    "Full access to the employee's document content. Use for any question about the document: content, summary, expiration date, dates, or other details. Input: message (e.g. 'What is the expiration date?', 'Summarize this document'). Optional document_ids to restrict to specific documents.",
  inputSchema: chatWithEmployeeDocumentsInputSchema,
};

export function createChatWithEmployeeDocumentsHandler(
  employeeDocumentsService: EmployeeDocumentsService,
  organizationId: string,
  employeeId: string,
  userId: string,
) {
  return async (args: { message: string; document_ids?: string[] }) => {
    const message = (args?.message ?? '').trim() || 'Summarize these documents.';
    const documentIds = args?.document_ids;
    const result = await employeeDocumentsService.chatOrSummarize(
      organizationId,
      employeeId,
      message,
      documentIds,
      userId,
    );
    const text = JSON.stringify({
      answer: result.answer,
      sources: result.sources,
    });
    return {
      content: [{ type: 'text' as const, text }],
    };
  };
}
