export interface McpRequestContext {
  patientId: string;
  auditContext?: {
    userId: string;
    ipAddress?: string;
    userAgent?: string;
  };
}

export interface McpAuthInfo {
  patientId: string;
}
