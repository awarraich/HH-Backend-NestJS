export const MCP_SERVER_NAME = 'digital-nurse';
export const MCP_SERVER_VERSION = '1.0.0';

export const TOOL_NAMES = {
  LIST_MEDICATIONS: 'list_medications',
  SEARCH_MEDICATIONS: 'search_medications',
  MARK_MEDICATION_TAKEN: 'mark_medication_taken',
  GET_DOCUMENT_EXPIRATION_STATUS: 'get_document_expiration_status',
  CHAT_WITH_EMPLOYEE_DOCUMENTS: 'chat_with_employee_document',
  LIST_COMPLIANCE_DOCUMENTS: 'list_compliance_documents',
  GET_COMPLIANCE_STATS: 'get_compliance_stats',
  GET_COMPLIANCE_DOCUMENT_DETAILS: 'get_compliance_document_details',
  SEARCH_COMPLIANCE_DOCUMENTS: 'search_compliance_documents',
  CHAT_WITH_COMPLIANCE_DOCUMENTS: 'chat_with_compliance_documents',
  GET_EXPIRING_DOCUMENTS_ALERT: 'get_expiring_documents_alert',
  ANALYZE_COMPLIANCE_DOCUMENT: 'analyze_compliance_document',
  COMPARE_COMPLIANCE_DOCUMENTS: 'compare_compliance_documents',
} as const;

export const MCP_ERROR_MESSAGES = {
  UNAUTHORIZED: 'Missing or invalid authorization',
  TOOL_NOT_FOUND: 'Tool not found',
  INTERNAL_ERROR: 'An error occurred while processing the request',
} as const;
