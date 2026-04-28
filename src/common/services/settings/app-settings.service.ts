import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { AppSetting, type AppSettingScope } from './entities/app-setting.entity';

export interface UpsertInput {
  key: string;
  scope: AppSettingScope;
  organizationId?: string | null;
  value: unknown;
  description?: string;
  updatedBy?: string;
}

interface CacheEntry {
  value: unknown;
  expiresAt: number;
}

const CACHE_TTL_MS = 30_000;

@Injectable()
export class AppSettingsService {
  private readonly logger = new Logger(AppSettingsService.name);
  // Per-process in-memory cache. PM2 cluster workers have independent caches;
  // toggle propagation across workers is bounded by CACHE_TTL_MS. Acceptable
  // for the change-rarely use case; not suitable for high-frequency toggles.
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    @InjectRepository(AppSetting)
    private readonly repo: Repository<AppSetting>,
  ) {}

  /**
   * Hot-path read used by the LlmRouter. Returns the resolved value with
   * per-org → global fallback. Returns null if neither row exists.
   */
  async getResolvedValue<T = unknown>(
    key: string,
    organizationId?: string | null,
  ): Promise<T | null> {
    if (organizationId) {
      const orgValue = await this.getValue<T>(key, organizationId);
      if (orgValue !== null) return orgValue;
    }
    return this.getValue<T>(key, null);
  }

  /** Read a single (key, scope) pair. organizationId=null means global. */
  async getValue<T = unknown>(
    key: string,
    organizationId: string | null,
  ): Promise<T | null> {
    const cacheKey = this.cacheKey(key, organizationId);
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.value as T | null;
    }

    const row = await this.repo.findOne({
      where: organizationId
        ? { key, scope: 'organization', organization_id: organizationId }
        : { key, scope: 'global', organization_id: IsNull() },
    });
    const value = (row?.value as T) ?? null;
    this.cache.set(cacheKey, {
      value,
      expiresAt: Date.now() + CACHE_TTL_MS,
    });
    return value;
  }

  async list(organizationIdFilter?: string): Promise<AppSetting[]> {
    if (organizationIdFilter) {
      return this.repo.find({
        where: { organization_id: organizationIdFilter },
        order: { key: 'ASC' },
      });
    }
    return this.repo.find({ order: { scope: 'ASC', key: 'ASC' } });
  }

  async listByKey(key: string): Promise<AppSetting[]> {
    return this.repo.find({ where: { key }, order: { scope: 'ASC' } });
  }

  async upsert(input: UpsertInput): Promise<AppSetting> {
    const orgId = input.scope === 'organization' ? (input.organizationId ?? null) : null;
    if (input.scope === 'organization' && !orgId) {
      throw new Error('organizationId required when scope is "organization"');
    }

    const existing = await this.repo.findOne({
      where: orgId
        ? { key: input.key, scope: 'organization', organization_id: orgId }
        : { key: input.key, scope: 'global', organization_id: IsNull() },
    });

    let saved: AppSetting;
    if (existing) {
      existing.value = input.value;
      if (input.description !== undefined) existing.description = input.description;
      if (input.updatedBy !== undefined) existing.updated_by = input.updatedBy;
      saved = await this.repo.save(existing);
    } else {
      const created = this.repo.create({
        key: input.key,
        scope: input.scope,
        organization_id: orgId,
        value: input.value,
        description: input.description ?? null,
        updated_by: input.updatedBy ?? null,
      });
      saved = await this.repo.save(created);
    }

    this.invalidate(input.key, orgId);
    this.logger.log(
      `setting upserted: key=${input.key} scope=${input.scope}${orgId ? ` org=${orgId}` : ''}`,
    );
    return saved;
  }

  async delete(
    key: string,
    scope: AppSettingScope,
    organizationId?: string | null,
  ): Promise<void> {
    const orgId = scope === 'organization' ? (organizationId ?? null) : null;
    if (scope === 'organization' && !orgId) {
      throw new Error('organizationId required when scope is "organization"');
    }
    const result = await this.repo.delete(
      orgId
        ? { key, scope: 'organization', organization_id: orgId }
        : { key, scope: 'global', organization_id: IsNull() },
    );
    if (!result.affected) {
      throw new NotFoundException(`Setting "${key}" not found`);
    }
    this.invalidate(key, orgId);
    this.logger.log(`setting deleted: key=${key} scope=${scope}${orgId ? ` org=${orgId}` : ''}`);
  }

  private cacheKey(key: string, organizationId: string | null): string {
    return `${key}|${organizationId ?? ''}`;
  }

  private invalidate(key: string, organizationId: string | null): void {
    this.cache.delete(this.cacheKey(key, organizationId));
  }
}
