export const MCP_SERVER_NAME = 'digital-nurse';
export const MCP_SERVER_VERSION = '1.0.0';

export const TOOL_NAMES = {
  LIST_MEDICATIONS: 'list_medications',
  SEARCH_MEDICATIONS: 'search_medications',
  MARK_MEDICATION_TAKEN: 'mark_medication_taken',
} as const;

export const MCP_ERROR_MESSAGES = {
  UNAUTHORIZED: 'Missing or invalid authorization',
  TOOL_NOT_FOUND: 'Tool not found',
  INTERNAL_ERROR: 'An error occurred while processing the request',
} as const;
