import { z } from 'zod';
import type { OrganizationDocumentsService } from '../../../models/organizations/compliance-documents/services/organization-documents.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {};

export const getComplianceStatsTool = {
  name: TOOL_NAMES.GET_COMPLIANCE_STATS,
  description:
    "Get compliance document statistics: total, valid, expiring soon, expired, and missing counts with per-category breakdown. Use when asked 'how is our compliance?', 'document status overview', or 'any documents expiring?'.",
  inputSchema,
};

export function createGetComplianceStatsHandler(
  service: OrganizationDocumentsService,
  organizationId: string,
) {
  return async () => {
    const result = await service.getStats(organizationId);
    return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
  };
}
