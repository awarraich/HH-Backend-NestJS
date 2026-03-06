import { z } from 'zod';
import type { EmployeeDocumentsService } from '../../../models/organizations/hr-files-setup/services/employee-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const getDocumentExpirationStatusInputSchema = {
  document_ids: z
    .array(z.string().uuid())
    .describe('Array of employee document UUIDs to check for expiration'),
};

export const getDocumentExpirationStatusTool = {
  name: TOOL_NAMES.GET_DOCUMENT_EXPIRATION_STATUS,
  description:
    "For a list of employee document IDs, returns whether each document is expired and expiration date derived from document content. Use when the user asks which documents are expired or about expiration status. Input: document_ids from the employee's required documents.",
  inputSchema: getDocumentExpirationStatusInputSchema,
};

export function createGetDocumentExpirationStatusHandler(
  employeeDocumentsService: EmployeeDocumentsService,
  organizationId: string,
  employeeId: string,
  userId: string,
) {
  return async (args: { document_ids: string[] }) => {
    const documentIds = args?.document_ids ?? [];
    const list = await employeeDocumentsService.getExpirationStatus(
      organizationId,
      employeeId,
      documentIds,
      userId,
    );
    const text = JSON.stringify(list, null, 2);
    return {
      content: [{ type: 'text' as const, text }],
    };
  };
}
