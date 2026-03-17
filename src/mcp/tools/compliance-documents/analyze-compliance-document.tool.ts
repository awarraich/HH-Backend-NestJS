import { z } from 'zod';
import type { OrganizationDocumentsChatService } from '../../../models/organizations/compliance-documents/services/organization-documents-chat.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';

const inputSchema = {
  document_id: z.string().uuid().describe('UUID of the document to analyze'),
  analysis_type: z
    .enum(['full', 'expiration', 'key_terms', 'summary', 'compliance_check'])
    .optional()
    .describe('Type of analysis (default: full)'),
};

export const analyzeComplianceDocumentTool = {
  name: TOOL_NAMES.ANALYZE_COMPLIANCE_DOCUMENT,
  description:
    "Deep AI analysis of a compliance document. Extracts key dates, parties, obligations, coverage, and compliance flags. Use for 'AI Scan', 'analyze this document', 'key terms?', or 'extract dates'.",
  inputSchema,
};

export function createAnalyzeComplianceDocumentHandler(
  chatService: OrganizationDocumentsChatService,
  organizationId: string,
) {
  return async (args: { document_id: string; analysis_type?: string }) => {
    const result = await chatService.analyzeDocument(
      organizationId,
      args.document_id,
      args.analysis_type ?? 'full',
    );
    return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
  };
}
