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
  // Scheduling — shifts
  LIST_SHIFTS: 'list_shifts',
  GET_SHIFT_DETAILS: 'get_shift_details',
  SEARCH_SHIFTS: 'search_shifts',
  GET_EMPLOYEE_SHIFTS: 'get_employee_shifts',
  // Scheduling — roles (modeled on EmployeeShift assignments)
  LIST_ROLES: 'list_roles',
  GET_ROLE_DETAILS: 'get_role_details',
  SEARCH_ROLES: 'search_roles',
  GET_EMPLOYEE_ROLES: 'get_employee_roles',
  GET_SHIFT_ROLES: 'get_shift_roles',
  // Scheduling — availability (fixture-backed)
  GET_EMPLOYEE_AVAILABILITY: 'get_employee_availability',
  SEARCH_AVAILABLE_EMPLOYEES: 'search_available_employees',
  GET_EMPLOYEE_AVAILABILITY_SCHEDULE: 'get_employee_availability_schedule',
  // Scheduling — employee directory (autonomous agent name → id resolution)
  LIST_EMPLOYEES: 'list_employees',
  SEARCH_EMPLOYEES: 'search_employees',
  LIST_EMPLOYEES_BY_ROLE: 'list_employees_by_role',
  LIST_EMPLOYEES_BY_ROLE_NAME: 'list_employees_by_role_name',
  // Scheduling — write
  ASSIGN_EMPLOYEE_TO_SHIFT: 'assign_employee_to_shift',
} as const;

export const MCP_ERROR_MESSAGES = {
  UNAUTHORIZED: 'Missing or invalid authorization',
  TOOL_NOT_FOUND: 'Tool not found',
  INTERNAL_ERROR: 'An error occurred while processing the request',
} as const;
