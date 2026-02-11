import { AuditLog } from '../entities/audit-log.entity';

export class AuditLogSerializer {
  serialize(log: AuditLog): Record<string, unknown> {
    return {
      id: log.id,
      user_id: log.user_id,
      action: log.action,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      description: log.description,
      metadata: log.metadata,
      ip_address: log.ip_address,
      user_agent: log.user_agent,
      status: log.status,
      error_message: log.error_message,
      created_at: log.created_at,
    };
  }

  serializeMany(logs: AuditLog[]): Record<string, unknown>[] {
    return logs.map((log) => this.serialize(log));
  }
}
