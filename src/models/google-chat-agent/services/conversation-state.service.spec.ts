import { ConversationStateService } from './conversation-state.service';
import {
  AgentTurn,
  CONVERSATION_TTL_MS,
  MAX_TURNS,
} from './conversation-state.types';
import { AgentRedisClient } from '../redis/agent-redis.client';

/**
 * Minimal in-memory fake of the Redis surface ConversationStateService uses.
 * Records the last TTL written so tests can assert TTL-reset behavior.
 */
class FakeAgentRedis {
  private store = new Map<string, string>();
  public lastPsetex: { key: string; ttlMs: number; value: string } | null =
    null;
  public deletedKeys: string[] = [];

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<unknown> {
    this.store.set(key, value);
    return 'OK';
  }

  async psetex(key: string, ttlMs: number, value: string): Promise<unknown> {
    this.store.set(key, value);
    this.lastPsetex = { key, ttlMs, value };
    return 'OK';
  }

  async del(key: string): Promise<number> {
    const existed = this.store.delete(key);
    this.deletedKeys.push(key);
    return existed ? 1 : 0;
  }

  async pttl(): Promise<number> {
    return this.lastPsetex?.ttlMs ?? -2;
  }

  /** Test helper: pre-seed a thread with a given JSON payload. */
  seed(key: string, value: string) {
    this.store.set(key, value);
  }

  /** Test helper: read raw stored JSON. */
  raw(key: string): string | undefined {
    return this.store.get(key);
  }
}

const buildService = (): {
  service: ConversationStateService;
  redis: FakeAgentRedis;
} => {
  const redis = new FakeAgentRedis();
  const service = new ConversationStateService(
    redis as unknown as AgentRedisClient,
  );
  return { service, redis };
};

const turn = (role: AgentTurn['role'], content: unknown): AgentTurn => ({
  role,
  content,
  ts: new Date().toISOString(),
});

const KEY = 'agent:thread:spaces/AAA/threads/BBB';
const THREAD = 'spaces/AAA/threads/BBB';

describe('ConversationStateService (M3)', () => {
  it('returns an empty array when no state exists', async () => {
    const { service } = buildService();
    expect(await service.get(THREAD)).toEqual([]);
  });

  it('returns the previously appended turns in order', async () => {
    const { service } = buildService();
    await service.append(THREAD, turn('user', 'hi'));
    await service.append(THREAD, turn('assistant', 'hello'));

    const state = await service.get(THREAD);
    expect(state.map((t) => t.content)).toEqual(['hi', 'hello']);
    expect(state.map((t) => t.role)).toEqual(['user', 'assistant']);
  });

  // M3-U1: append rolls window when length > MAX_TURNS (oldest dropped).
  it('caps history at MAX_TURNS, dropping the oldest', async () => {
    const { service } = buildService();
    for (let i = 0; i < MAX_TURNS + 5; i++) {
      await service.append(THREAD, turn('user', `msg-${i}`));
    }

    const state = await service.get(THREAD);
    expect(state).toHaveLength(MAX_TURNS);
    // First retained should be msg-5 (we appended 0..16, kept the last 12).
    expect(state[0].content).toBe('msg-5');
    expect(state[MAX_TURNS - 1].content).toBe(`msg-${MAX_TURNS + 4}`);
  });

  // M3-U2: clear removes the key.
  it('clear deletes the thread state', async () => {
    const { service, redis } = buildService();
    await service.append(THREAD, turn('user', 'hi'));
    await service.clear(THREAD);

    expect(await service.get(THREAD)).toEqual([]);
    expect(redis.deletedKeys).toContain(KEY);
  });

  // M3-U3: TTL is reset on every append.
  it('resets the TTL on every append (writes via psetex)', async () => {
    const { service, redis } = buildService();
    await service.append(THREAD, turn('user', 'one'));
    expect(redis.lastPsetex).toEqual({
      key: KEY,
      ttlMs: CONVERSATION_TTL_MS,
      value: expect.any(String),
    });

    const firstWriteTtl = redis.lastPsetex!.ttlMs;
    await service.append(THREAD, turn('assistant', 'two'));
    expect(redis.lastPsetex!.ttlMs).toBe(firstWriteTtl);
  });

  it('treats corrupt JSON in storage as an empty thread without throwing', async () => {
    const { service, redis } = buildService();
    redis.seed(KEY, '{this is not valid json');

    expect(await service.get(THREAD)).toEqual([]);
    // Subsequent append should still work.
    await service.append(THREAD, turn('user', 'recovery'));
    const state = await service.get(THREAD);
    expect(state.map((t) => t.content)).toEqual(['recovery']);
  });

  it('treats non-array JSON as empty (defensive)', async () => {
    const { service, redis } = buildService();
    redis.seed(KEY, '{"not":"an array"}');
    expect(await service.get(THREAD)).toEqual([]);
  });

  it('keys are namespaced with the agent: prefix and thread: segment', async () => {
    const { service, redis } = buildService();
    await service.append(THREAD, turn('user', 'x'));
    expect(redis.lastPsetex!.key).toBe(KEY);
    expect(redis.raw(KEY)).toBeDefined();
  });

  it('isolates state across different threads', async () => {
    const { service } = buildService();
    await service.append('thread-A', turn('user', 'A1'));
    await service.append('thread-B', turn('user', 'B1'));
    await service.append('thread-A', turn('user', 'A2'));

    const a = await service.get('thread-A');
    const b = await service.get('thread-B');
    expect(a.map((t) => t.content)).toEqual(['A1', 'A2']);
    expect(b.map((t) => t.content)).toEqual(['B1']);
  });
});
