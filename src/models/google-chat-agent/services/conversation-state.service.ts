import { Injectable, Logger } from '@nestjs/common';
import {
  AgentRedisClient,
  AGENT_REDIS_KEY_PREFIX,
} from '../redis/agent-redis.client';
import {
  AgentTurn,
  CONVERSATION_TTL_MS,
  MAX_TURNS,
} from './conversation-state.types';

/**
 * Per-Chat-thread short-term memory for the agent.
 *
 * Stores up to MAX_TURNS most recent turns under a single Redis key per
 * thread, with a TTL that resets on every append. Conversation state only —
 * NEVER caches business data (shifts, availability, etc.). Tool results are
 * recomputed against the DB on every turn so a change made via the web UI
 * is immediately reflected in the next bot reply.
 *
 * On corrupt JSON in Redis (rare; manual edit or upstream bug), behaves as
 * if the thread had no history — the next turn rebuilds from empty.
 */
@Injectable()
export class ConversationStateService {
  private readonly logger = new Logger(ConversationStateService.name);

  constructor(private readonly redis: AgentRedisClient) {}

  async get(threadKey: string): Promise<AgentTurn[]> {
    const raw = await this.redis.get(this.key(threadKey));
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed as AgentTurn[];
    } catch {
      this.logger.warn(
        `Corrupt conversation state for thread ${threadKey}; treating as empty.`,
      );
      return [];
    }
  }

  async append(threadKey: string, turn: AgentTurn): Promise<void> {
    const existing = await this.get(threadKey);
    const next = [...existing, turn];
    const trimmed =
      next.length > MAX_TURNS ? next.slice(next.length - MAX_TURNS) : next;
    await this.redis.psetex(
      this.key(threadKey),
      CONVERSATION_TTL_MS,
      JSON.stringify(trimmed),
    );
  }

  async clear(threadKey: string): Promise<void> {
    await this.redis.del(this.key(threadKey));
  }

  private key(threadKey: string): string {
    return `${AGENT_REDIS_KEY_PREFIX}thread:${threadKey}`;
  }
}
