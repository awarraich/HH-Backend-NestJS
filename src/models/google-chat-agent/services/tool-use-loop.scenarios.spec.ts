import { z } from 'zod';
import type { ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { ToolRegistry } from '../tools/tool.registry';
import { runToolUseLoop } from './tool-use-loop';
import {
  scriptedOpenAI,
  textResponse,
  toolCallResponse,
} from './__test_helpers__/scripted-llm';
import type { AgentContext } from '../tools/tool.types';

const ctx = (): AgentContext => ({
  user: {
    userId: 'user-1',
    organizationId: 'org-1',
    timezone: 'UTC',
    chatUserId: 'users/x',
    chatSpaceName: 'spaces/x',
  },
  turnId: 'turn-test',
});

const buildRegistry = () => {
  const registry = new ToolRegistry();
  registry.register({
    name: 'echo',
    description: 'echoes input',
    input: z.object({ msg: z.string() }),
    output: z.object({ said: z.string() }),
    handler: async (input) => ({ said: input.msg }),
  });
  registry.register({
    name: 'broken',
    description: 'always throws',
    input: z.object({}),
    output: z.object({}),
    handler: async () => {
      throw new Error('boom');
    },
  });
  return registry;
};

describe('runToolUseLoop — multi-turn scenarios (OpenAI)', () => {
  // SCENARIO: model proposes an action and asks for confirmation.
  // Then on the user's "Yes", model calls the tool.
  // We verify that history (including the prior assistant question) is
  // forwarded to the LLM on the confirmation turn, AND that "Yes" → tool_call
  // chains correctly.
  it('threads prior history into the LLM and acts on confirmation', async () => {
    const history: ChatCompletionMessageParam[] = [
      {
        role: 'user',
        content: 'Set my Tuesday availability to 9-5',
      },
      {
        role: 'assistant',
        content: 'Just to confirm — set Tuesday 9-5 (recurring)?',
      },
    ];
    const client = scriptedOpenAI([
      // First call (the user's "Yes" turn): model issues tool_call.
      toolCallResponse([
        {
          name: 'echo',
          argsJson: JSON.stringify({ msg: 'Tuesday 9-5 set' }),
        },
      ]),
      // After tool dispatch + tool_result message, model produces final text.
      textResponse('Done — Tuesday 9-5 saved.'),
    ]);

    const registry = buildRegistry();
    const result = await runToolUseLoop({
      provider: 'openai',
      client: client as unknown as Parameters<typeof runToolUseLoop>[0] extends {
        client: infer C;
      }
        ? C
        : never,
      model: 'gpt-4o',
      maxTokens: 1024,
      systemPrompt: 'system',
      history,
      userText: 'Yes',
      ctx: ctx(),
      registry,
      tools: registry.getOpenAIToolsPayload(),
    });

    // First LLM call carries: system, prior history, then user "Yes".
    expect(client.__calls[0].messages).toEqual([
      { role: 'system', content: 'system' },
      ...history,
      { role: 'user', content: 'Yes' },
    ]);

    // Second LLM call (post-tool-dispatch) preserves the assistant tool_call
    // turn AND adds a `role: 'tool'` message keyed by tool_call_id.
    const secondCallMessages = client.__calls[1].messages;
    const toolMsg = secondCallMessages.find((m) => m.role === 'tool');
    expect(toolMsg).toBeDefined();
    const assistantToolCallTurn = secondCallMessages.find(
      (m) => m.role === 'assistant' && 'tool_calls' in m && m.tool_calls,
    );
    expect(assistantToolCallTurn).toBeDefined();

    expect(result.text).toBe('Done — Tuesday 9-5 saved.');
    expect(result.toolCalls).toEqual([
      expect.objectContaining({ name: 'echo', ok: true }),
    ]);
    expect(result.lastToolName).toBe('echo');
  });

  it('aggregates token usage across all LLM calls in the loop', async () => {
    const client = scriptedOpenAI([
      toolCallResponse(
        [{ name: 'echo', argsJson: JSON.stringify({ msg: 'hi' }) }],
        { promptTokens: 100, completionTokens: 20 },
      ),
      textResponse('all done', { promptTokens: 250, completionTokens: 5 }),
    ]);
    const registry = buildRegistry();
    const result = await runToolUseLoop({
      provider: 'openai',
      client: client as never,
      model: 'gpt-4o',
      maxTokens: 1024,
      systemPrompt: 'sys',
      history: [],
      userText: 'go',
      ctx: ctx(),
      registry,
      tools: registry.getOpenAIToolsPayload(),
    });
    expect(result.tokensIn).toBe(350);
    expect(result.tokensOut).toBe(25);
  });

  it('captures tool errors as is_error tool_result messages and lets the loop recover', async () => {
    const client = scriptedOpenAI([
      // Model calls the broken tool first
      toolCallResponse([{ name: 'broken', argsJson: '{}' }]),
      // After seeing the error, model produces a graceful message
      textResponse('I hit an error trying that. Try again later.'),
    ]);
    const registry = buildRegistry();
    const result = await runToolUseLoop({
      provider: 'openai',
      client: client as never,
      model: 'gpt-4o',
      maxTokens: 1024,
      systemPrompt: 'sys',
      history: [],
      userText: 'try the broken thing',
      ctx: ctx(),
      registry,
      tools: registry.getOpenAIToolsPayload(),
    });

    // The tool message back to the model should be a non-throwing tool_result
    // explaining the error, NOT a thrown exception.
    const secondCallToolMsg = client.__calls[1].messages.find(
      (m) => m.role === 'tool',
    );
    expect(secondCallToolMsg).toBeDefined();
    if (secondCallToolMsg && 'content' in secondCallToolMsg) {
      expect(String(secondCallToolMsg.content)).toMatch(/Tool error/i);
    }

    expect(result.text).toMatch(/error/i);
    expect(result.toolCalls).toEqual([
      expect.objectContaining({ name: 'broken', ok: false }),
    ]);
  });

  it('handles plain text responses (no tools) without dispatching anything', async () => {
    const client = scriptedOpenAI([textResponse('hello there')]);
    const registry = buildRegistry();
    const result = await runToolUseLoop({
      provider: 'openai',
      client: client as never,
      model: 'gpt-4o',
      maxTokens: 1024,
      systemPrompt: 'sys',
      history: [],
      userText: 'hi',
      ctx: ctx(),
      registry,
      tools: registry.getOpenAIToolsPayload(),
    });
    expect(result.text).toBe('hello there');
    expect(result.toolCalls).toEqual([]);
    expect(result.lastToolName).toBeNull();
    expect(client.__calls).toHaveLength(1);
  });

  it('chains multiple tool calls in one turn and reports the LAST as lastToolName', async () => {
    const client = scriptedOpenAI([
      // Model calls two tools in parallel on the first response
      toolCallResponse([
        { id: 'c1', name: 'echo', argsJson: JSON.stringify({ msg: 'A' }) },
        { id: 'c2', name: 'echo', argsJson: JSON.stringify({ msg: 'B' }) },
      ]),
      textResponse('both done'),
    ]);
    const registry = buildRegistry();
    const result = await runToolUseLoop({
      provider: 'openai',
      client: client as never,
      model: 'gpt-4o',
      maxTokens: 1024,
      systemPrompt: 'sys',
      history: [],
      userText: 'do both',
      ctx: ctx(),
      registry,
      tools: registry.getOpenAIToolsPayload(),
    });
    expect(result.toolCalls).toHaveLength(2);
    // Both succeeded; lastToolName is the second one dispatched.
    expect(result.lastToolName).toBe('echo');
    expect((result.lastToolOutput as { said: string }).said).toBe('B');
  });
});
