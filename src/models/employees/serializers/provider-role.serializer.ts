import { ProviderRole } from '../entities/provider-role.entity';

export class ProviderRoleSerializer {
  serialize(role: ProviderRole): Record<string, unknown> {
    return {
      id: role.id,
      code: role.code,
      name: role.name,
      description: role.description ?? null,
      created_at: role.created_at,
    };
  }

  serializeMany(roles: ProviderRole[]): Record<string, unknown>[] {
    return roles.map((role) => this.serialize(role));
  }
}
