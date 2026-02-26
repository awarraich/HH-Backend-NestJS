import type { EmployeeDocumentsService } from '../../../models/organizations/hr-files-setup/services/employee-documents.service';
import {
  getDocumentExpirationStatusTool,
  createGetDocumentExpirationStatusHandler,
} from './get-document-expiration-status.tool';
import {
  chatWithEmployeeDocumentsTool,
  createChatWithEmployeeDocumentsHandler,
} from './chat-with-employee-documents.tool';

export function registerEmployeeDocumentHandlers(
  employeeDocumentsService: EmployeeDocumentsService,
  organizationId: string,
  employeeId: string,
  userId: string,
) {
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
