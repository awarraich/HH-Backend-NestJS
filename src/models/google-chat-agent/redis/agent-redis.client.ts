import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import Redis, { type RedisOptions } from 'ioredis';

/**
 * The Redis client wrapper used by the Google Chat agent module.
 * Owns its own connection rather than reusing BullMQ's so failures
 * in the agent's Redis traffic don't impact queue health.
 *
 * Reads the same REDIS_HOST / REDIS_PORT env vars the rest of the app
 * uses (see app.module.ts BullMQ wiring). All keys this module writes
 * are prefixed `agent:` to keep them visually distinct in tooling.
 */
export const AGENT_REDIS_KEY_PREFIX = 'agent:';

export const AGENT_REDIS_CLIENT_TOKEN = Symbol('AGENT_REDIS_CLIENT');

export interface AgentRedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  psetex(key: string, ttlMs: number, value: string): Promise<unknown>;
  del(key: string): Promise<number>;
  pttl(key: string): Promise<number>;
  quit?(): Promise<unknown>;
}

@Injectable()
export class AgentRedisClient implements OnModuleDestroy, AgentRedisLike {
  private readonly logger = new Logger(AgentRedisClient.name);
  private readonly client: Redis | null;

  constructor(@Inject(AGENT_REDIS_CLIENT_TOKEN) injected: Redis | null) {
    this.client = injected;
  }

  private getClient(): Redis {
    if (!this.client) {
      throw new Error(
        'AgentRedisClient: underlying ioredis client is not initialized.',
      );
    }
    return this.client;
  }

  get(key: string): Promise<string | null> {
    return this.getClient().get(key);
  }

  set(key: string, value: string): Promise<unknown> {
    return this.getClient().set(key, value);
  }

  psetex(key: string, ttlMs: number, value: string): Promise<unknown> {
    return this.getClient().set(key, value, 'PX', ttlMs);
  }

  del(key: string): Promise<number> {
    return this.getClient().del(key);
  }

  pttl(key: string): Promise<number> {
    return this.getClient().pttl(key);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client) {
      try {
        await this.client.quit();
      } catch (err) {
        this.logger.warn(`Error closing agent Redis client: ${String(err)}`);
      }
    }
  }
}

/**
 * Factory provider for the underlying ioredis instance. Kept separate
 * from AgentRedisClient so tests can `useValue` a mock for the token
 * while keeping the AgentRedisClient class shape intact.
 */
export const agentRedisClientProvider = {
  provide: AGENT_REDIS_CLIENT_TOKEN,
  useFactory: (): Redis => {
    const options: RedisOptions = {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: parseInt(process.env.REDIS_PORT || '6379', 10),
      lazyConnect: true,
      maxRetriesPerRequest: null,
    };
    return new Redis(options);
  },
};
