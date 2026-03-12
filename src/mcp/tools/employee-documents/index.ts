import type { EmployeeDocumentsService } from '../../../models/organizations/hr-files-setup/services/employee-documents.service';
import {
  getDocumentExpirationStatusTool,
  createGetDocumentExpirationStatusHandler,
} from './get-document-expiration-status.tool';
import {
  chatWithEmployeeDocumentsTool,
  createChatWithEmployeeDocumentsHandler,
} from './chat-with-employee-documents.tool';

export type McpToolResult = Promise<{ content: Array<{ type: 'text'; text: string }> }>;

export function registerEmployeeDocumentHandlers(
  employeeDocumentsService: EmployeeDocumentsService,
  organizationId: string,
  employeeId: string,
  userId: string,
): Array<{
  name: string;
  description: string;
  inputSchema: object;
  handler: (args: unknown) => McpToolResult;
}> {
  return [
    {
      ...getDocumentExpirationStatusTool,
      handler: createGetDocumentExpirationStatusHandler(
        employeeDocumentsService,
        organizationId,
        employeeId,
        userId,
      ),
    },
    {
      ...chatWithEmployeeDocumentsTool,
      handler: createChatWithEmployeeDocumentsHandler(
        employeeDocumentsService,
        organizationId,
        employeeId,
        userId,
      ),
    },
  ];
}
