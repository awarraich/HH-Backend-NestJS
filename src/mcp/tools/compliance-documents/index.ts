import type { OrganizationDocumentsService } from '../../../models/organizations/compliance-documents/services/organization-documents.service';
import type { OrganizationDocumentsChatService } from '../../../models/organizations/compliance-documents/services/organization-documents-chat.service';
import { listComplianceDocumentsTool, createListComplianceDocumentsHandler } from './list-compliance-documents.tool';
import { getComplianceStatsTool, createGetComplianceStatsHandler } from './get-compliance-stats.tool';
import { getComplianceDocumentDetailsTool, createGetComplianceDocumentDetailsHandler } from './get-compliance-document-details.tool';
import { searchComplianceDocumentsTool, createSearchComplianceDocumentsHandler } from './search-compliance-documents.tool';
import { chatWithComplianceDocumentsTool, createChatWithComplianceDocumentsHandler } from './chat-with-compliance-documents.tool';
import { getExpiringDocumentsAlertTool, createGetExpiringDocumentsAlertHandler } from './get-expiring-documents-alert.tool';
import { analyzeComplianceDocumentTool, createAnalyzeComplianceDocumentHandler } from './analyze-compliance-document.tool';
import { compareComplianceDocumentsTool, createCompareComplianceDocumentsHandler } from './compare-compliance-documents.tool';

export type McpToolResult = Promise<{ content: Array<{ type: 'text'; text: string }> }>;

export function registerComplianceDocumentHandlers(
  documentsService: OrganizationDocumentsService,
  chatService: OrganizationDocumentsChatService,
  organizationId: string,
): Array<{
  name: string;
  description: string;
  inputSchema: object;
  handler: (args: unknown) => McpToolResult;
}> {
  return [
    {
      ...listComplianceDocumentsTool,
      handler: createListComplianceDocumentsHandler(documentsService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...getComplianceStatsTool,
      handler: createGetComplianceStatsHandler(documentsService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...getComplianceDocumentDetailsTool,
      handler: createGetComplianceDocumentDetailsHandler(documentsService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...searchComplianceDocumentsTool,
      handler: createSearchComplianceDocumentsHandler(documentsService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...chatWithComplianceDocumentsTool,
      handler: createChatWithComplianceDocumentsHandler(chatService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...getExpiringDocumentsAlertTool,
      handler: createGetExpiringDocumentsAlertHandler(documentsService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...analyzeComplianceDocumentTool,
      handler: createAnalyzeComplianceDocumentHandler(chatService, organizationId) as (args: unknown) => McpToolResult,
    },
    {
      ...compareComplianceDocumentsTool,
      handler: createCompareComplianceDocumentsHandler(chatService, organizationId) as (args: unknown) => McpToolResult,
    },
  ];
}
