import { z } from 'zod';
import type { OrganizationDocumentsService } from '../../../models/organizations/compliance-documents/services/organization-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  days_ahead: z
    .number()
    .int()
    .min(1)
    .max(365)
    .optional()
    .describe('Look-ahead window in days (default 90)'),
};

export const getExpiringDocumentsAlertTool = {
  name: TOOL_NAMES.GET_EXPIRING_DOCUMENTS_ALERT,
  description:
    "Prioritized compliance alerts: expired, expiring soon, and missing required documents sorted by urgency. Use when asked 'what needs attention?', 'compliance issues?', or 'overdue documents?'.",
  inputSchema,
};

export function createGetExpiringDocumentsAlertHandler(
  service: OrganizationDocumentsService,
  organizationId: string,
) {
  return async (args: { days_ahead?: number }) => {
    const result = await service.getExpiringDocuments(organizationId, args.days_ahead ?? 90);
    return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
  };
}
