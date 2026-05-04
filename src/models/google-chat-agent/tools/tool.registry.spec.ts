import { z } from 'zod';
import { ToolRegistry } from './tool.registry';
import {
  AgentContext,
  DuplicateToolError,
  Tool,
  ToolInputValidationError,
  ToolNotFoundError,
  ToolOutputValidationError,
} from './tool.types';

const ctx = (): AgentContext => ({
  user: {
    userId: 'user-uuid-1',
    organizationId: 'org-uuid-1',
    timezone: 'UTC',
    chatUserId: 'users/123',
    chatSpaceName: 'spaces/AAA',
  },
  turnId: 'turn-1',
});

const pingTool = (): Tool<{ msg: string }, { reply: string }> => ({
  name: 'ping',
  description: 'Echoes a message',
  input: z.object({ msg: z.string() }),
  output: z.object({ reply: z.string() }),
  handler: async (input) => ({ reply: `pong: ${input.msg}` }),
});

describe('ToolRegistry (M4)', () => {
  // M4-U1: Registry rejects two tools with the same name.
  it('rejects duplicate tool names', () => {
    const registry = new ToolRegistry();
    registry.register(pingTool());
    expect(() => registry.register(pingTool())).toThrow(DuplicateToolError);
  });

  it('list() and size() reflect registered tools', () => {
    const registry = new ToolRegistry();
    expect(registry.size()).toBe(0);
    registry.register(pingTool());
    expect(registry.size()).toBe(1);
    expect(registry.list()).toEqual(['ping']);
    expect(registry.has('ping')).toBe(true);
    expect(registry.has('nope')).toBe(false);
  });

  // M4-U2: getAnthropicToolsPayload produces JSON Schema with
  // additionalProperties: false matching the Zod shape.
  it('produces an Anthropic tools payload with strict input schemas', () => {
    const registry = new ToolRegistry();
    registry.register({
      name: 'listMyShifts',
      description: 'list the caller shifts',
      input: z.object({
        from: z.string().optional(),
        limit: z.number().int().min(1).max(50).default(10),
      }),
      output: z.array(z.object({ id: z.string() })),
      handler: async () => [],
    });

    const payload = registry.getAnthropicToolsPayload();
    expect(payload).toHaveLength(1);
    expect(payload[0].name).toBe('listMyShifts');
    expect(payload[0].input_schema.type).toBe('object');
    expect(payload[0].input_schema.additionalProperties).toBe(false);
    expect(payload[0].input_schema.properties).toMatchObject({
      from: { type: 'string' },
      limit: { type: 'integer' },
    });
  });

  it('omits $schema and definitions metadata from the input_schema', () => {
    const registry = new ToolRegistry();
    registry.register(pingTool());
    const [first] = registry.getAnthropicToolsPayload();
    expect((first.input_schema as Record<string, unknown>).$schema).toBeUndefined();
    expect((first.input_schema as Record<string, unknown>).definitions).toBeUndefined();
  });

  // Prompt-cache breakpoint should land on the LAST tool only.
  it('attaches cache_control: ephemeral to the last tool only', () => {
    const registry = new ToolRegistry();
    for (const n of ['a', 'b', 'c']) {
      registry.register({
        name: n,
        description: `tool ${n}`,
        input: z.object({}),
        output: z.object({}),
        handler: async () => ({}),
      });
    }
    const payload = registry.getAnthropicToolsPayload();
    expect(payload[0].cache_control).toBeUndefined();
    expect(payload[1].cache_control).toBeUndefined();
    expect(payload[2].cache_control).toEqual({ type: 'ephemeral' });
  });

  it('returns an empty payload when no tools are registered', () => {
    const registry = new ToolRegistry();
    expect(registry.getAnthropicToolsPayload()).toEqual([]);
  });

  // OpenAI tools payload — wraps each tool in {type:'function', function:{...}}.
  it('produces an OpenAI tools payload with the correct outer shape', () => {
    const registry = new ToolRegistry();
    registry.register({
      name: 'listMyShifts',
      description: 'list the caller shifts',
      input: z.object({
        from: z.string().optional(),
      }),
      output: z.array(z.object({ id: z.string() })),
      handler: async () => [],
    });

    const payload = registry.getOpenAIToolsPayload();
    expect(payload).toHaveLength(1);
    expect(payload[0].type).toBe('function');
    expect(payload[0].function.name).toBe('listMyShifts');
    expect(payload[0].function.description).toBe('list the caller shifts');
    expect(payload[0].function.parameters.type).toBe('object');
    expect(payload[0].function.parameters.additionalProperties).toBe(false);
    expect(payload[0].function.parameters.properties).toMatchObject({
      from: { type: 'string' },
    });
  });

  it('OpenAI payload is empty when no tools registered', () => {
    const registry = new ToolRegistry();
    expect(registry.getOpenAIToolsPayload()).toEqual([]);
  });

  it('OpenAI payload omits $schema and definitions metadata', () => {
    const registry = new ToolRegistry();
    registry.register(pingTool());
    const [first] = registry.getOpenAIToolsPayload();
    expect((first.function.parameters as Record<string, unknown>).$schema).toBeUndefined();
    expect((first.function.parameters as Record<string, unknown>).definitions).toBeUndefined();
  });

  // M4-U3: dispatch unknown name throws ToolNotFoundError.
  it('dispatch on an unknown tool throws ToolNotFoundError', async () => {
    const registry = new ToolRegistry();
    await expect(registry.dispatch('unknown', {}, ctx())).rejects.toThrow(
      ToolNotFoundError,
    );
  });

  it('dispatch validates input via Zod and throws ToolInputValidationError on mismatch', async () => {
    const registry = new ToolRegistry();
    registry.register(pingTool());
    await expect(
      registry.dispatch('ping', { msg: 123 }, ctx()),
    ).rejects.toThrow(ToolInputValidationError);
  });

  it('dispatch passes the parsed input and context to the handler', async () => {
    const registry = new ToolRegistry();
    const handler = jest.fn().mockResolvedValue({ reply: 'pong: hello' });
    registry.register({
      name: 'ping',
      description: '',
      input: z.object({ msg: z.string() }),
      output: z.object({ reply: z.string() }),
      handler,
    });

    const c = ctx();
    await registry.dispatch('ping', { msg: 'hello' }, c);
    expect(handler).toHaveBeenCalledWith({ msg: 'hello' }, c);
  });

  // M4-U4: Output that fails the Zod schema raises before being returned.
  it('throws ToolOutputValidationError when handler output does not match the schema', async () => {
    const registry = new ToolRegistry();
    registry.register({
      name: 'buggy',
      description: '',
      input: z.object({}),
      output: z.object({ count: z.number() }),
      // @ts-expect-error - intentionally returning the wrong shape to test the validator
      handler: async () => ({ count: 'not a number' }),
    });
    await expect(registry.dispatch('buggy', {}, ctx())).rejects.toThrow(
      ToolOutputValidationError,
    );
  });

  it('propagates handler exceptions unchanged', async () => {
    const registry = new ToolRegistry();
    const boom = new Error('database down');
    registry.register({
      name: 'broken',
      description: '',
      input: z.object({}),
      output: z.object({}),
      handler: async () => {
        throw boom;
      },
    });
    await expect(registry.dispatch('broken', {}, ctx())).rejects.toBe(boom);
  });

  it('applies Zod defaults during input validation', async () => {
    const registry = new ToolRegistry();
    let captured: { limit?: number } | null = null;
    registry.register({
      name: 'paged',
      description: '',
      input: z.object({ limit: z.number().int().default(10) }),
      output: z.object({ ok: z.boolean() }),
      handler: async (input) => {
        captured = input;
        return { ok: true };
      },
    });

    await registry.dispatch('paged', {}, ctx());
    expect(captured).toEqual({ limit: 10 });
  });
});
