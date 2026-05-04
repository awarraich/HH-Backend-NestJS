import { Logger } from '@nestjs/common';
import type Anthropic from '@anthropic-ai/sdk';
import type {
  Message,
  MessageParam,
  TextBlock,
  ToolUseBlock,
} from '@anthropic-ai/sdk/resources/messages';
import type OpenAI from 'openai';
import type { ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { ToolRegistry } from '../tools/tool.registry';
import {
  AgentContext,
  AnthropicToolPayload,
  OpenAIToolPayload,
} from '../tools/tool.types';

const MAX_LOOP_ITERATIONS = 6;

export interface ToolUseLoopResult {
  text: string;
  lastToolName: string | null;
  lastToolOutput: unknown | null;
  toolCalls: Array<{ name: string; ok: boolean; input?: unknown; output?: unknown; error?: string }>;
  /** Aggregate token usage across all LLM calls in this loop. */
  tokensIn: number;
  tokensOut: number;
}

export interface AnthropicLoopOptions {
  provider: 'anthropic';
  client: Anthropic;
  model: string;
  maxTokens: number;
  systemPrompt: string;
  history: MessageParam[];
  userText: string;
  ctx: AgentContext;
  registry: ToolRegistry;
  tools: AnthropicToolPayload[];
  logger?: Logger;
}

export interface OpenAILoopOptions {
  provider: 'openai';
  client: OpenAI;
  model: string;
  maxTokens: number;
  systemPrompt: string;
  history: ChatCompletionMessageParam[];
  userText: string;
  ctx: AgentContext;
  registry: ToolRegistry;
  tools: OpenAIToolPayload[];
  logger?: Logger;
}

export type ToolUseLoopOptions = AnthropicLoopOptions | OpenAILoopOptions;

/**
 * Provider-aware dispatcher. Picks the right loop implementation based
 * on `opts.provider`. The two implementations share the same return shape
 * but speak different SDKs internally.
 */
export async function runToolUseLoop(
  opts: ToolUseLoopOptions,
): Promise<ToolUseLoopResult> {
  if (opts.provider === 'anthropic') return runAnthropicLoop(opts);
  return runOpenAILoop(opts);
}

/**
 * Anthropic SDK tool-use orchestration.
 *   user message → Claude → (tool_use* → dispatch → tool_result*)* → text → return
 */
async function runAnthropicLoop(
  opts: AnthropicLoopOptions,
): Promise<ToolUseLoopResult> {
  const log = opts.logger ?? new Logger('ToolUseLoop:anthropic');
  const messages: MessageParam[] = [
    ...opts.history,
    { role: 'user', content: opts.userText },
  ];
  let lastToolName: string | null = null;
  let lastToolOutput: unknown | null = null;
  const toolCalls: ToolUseLoopResult['toolCalls'] = [];
  let tokensIn = 0;
  let tokensOut = 0;

  for (let i = 0; i < MAX_LOOP_ITERATIONS; i++) {
    const response: Message = await opts.client.messages.create({
      model: opts.model,
      max_tokens: opts.maxTokens,
      system: [
        {
          type: 'text',
          text: opts.systemPrompt,
          cache_control: { type: 'ephemeral' },
        },
      ],
      tools: opts.tools as never,
      messages,
    });

    tokensIn += response.usage?.input_tokens ?? 0;
    tokensOut += response.usage?.output_tokens ?? 0;

    const toolUseBlocks = response.content.filter(
      (b): b is ToolUseBlock => b.type === 'tool_use',
    );

    if (response.stop_reason !== 'tool_use' || toolUseBlocks.length === 0) {
      const text = response.content
        .filter((b): b is TextBlock => b.type === 'text')
        .map((b) => b.text)
        .join('\n')
        .trim();
      return {
        text:
          text ||
          "I'm not sure how to answer that — could you rephrase or give me more detail?",
        lastToolName,
        lastToolOutput,
        toolCalls,
        tokensIn,
        tokensOut,
      };
    }

    messages.push({ role: 'assistant', content: response.content });

    const toolResultContent: MessageParam['content'] = [];
    for (const block of toolUseBlocks) {
      try {
        const result = await opts.registry.dispatch(
          block.name,
          block.input,
          opts.ctx,
        );
        lastToolName = block.name;
        lastToolOutput = result;
        toolCalls.push({
          name: block.name,
          ok: true,
          input: block.input,
          output: result,
        });
        toolResultContent.push({
          type: 'tool_result',
          tool_use_id: block.id,
          content: JSON.stringify(result),
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log.warn(`Tool ${block.name} threw: ${message}`);
        toolCalls.push({
          name: block.name,
          ok: false,
          input: block.input,
          error: message,
        });
        toolResultContent.push({
          type: 'tool_result',
          tool_use_id: block.id,
          content: `Tool error: ${message}`,
          is_error: true,
        });
      }
    }
    messages.push({ role: 'user', content: toolResultContent });
  }

  log.warn(
    `Anthropic tool-use loop hit MAX_LOOP_ITERATIONS=${MAX_LOOP_ITERATIONS} without resolving.`,
  );
  return {
    text:
      "I'm taking too long to work this out — please try a more specific question.",
    lastToolName,
    lastToolOutput,
    toolCalls,
    tokensIn,
    tokensOut,
  };
}

/**
 * OpenAI Chat Completions tool-use orchestration.
 *   system + user → GPT → (tool_calls* → dispatch → tool messages*)* → text → return
 *
 * Differences from the Anthropic loop:
 *   - System prompt is a regular `role: 'system'` message, not a top-level field.
 *   - Tool calls live on `message.tool_calls`; each is dispatched and the
 *     result is sent back as a `role: 'tool'` message keyed by `tool_call_id`.
 *   - No explicit cache_control; OpenAI caches prompt prefixes server-side.
 */
async function runOpenAILoop(
  opts: OpenAILoopOptions,
): Promise<ToolUseLoopResult> {
  const log = opts.logger ?? new Logger('ToolUseLoop:openai');
  const messages: ChatCompletionMessageParam[] = [
    { role: 'system', content: opts.systemPrompt },
    ...opts.history,
    { role: 'user', content: opts.userText },
  ];
  let lastToolName: string | null = null;
  let lastToolOutput: unknown | null = null;
  const toolCalls: ToolUseLoopResult['toolCalls'] = [];
  let tokensIn = 0;
  let tokensOut = 0;

  for (let i = 0; i < MAX_LOOP_ITERATIONS; i++) {
    const response = await opts.client.chat.completions.create({
      model: opts.model,
      max_tokens: opts.maxTokens,
      messages,
      tools: opts.tools as never,
    });

    tokensIn += response.usage?.prompt_tokens ?? 0;
    tokensOut += response.usage?.completion_tokens ?? 0;

    const choice = response.choices[0];
    const assistantMessage = choice.message;
    const toolCallBlocks = assistantMessage.tool_calls ?? [];

    if (toolCallBlocks.length === 0) {
      const text = (assistantMessage.content ?? '').toString().trim();
      return {
        text:
          text ||
          "I'm not sure how to answer that — could you rephrase or give me more detail?",
        lastToolName,
        lastToolOutput,
        toolCalls,
        tokensIn,
        tokensOut,
      };
    }

    messages.push({
      role: 'assistant',
      content: assistantMessage.content ?? null,
      tool_calls: toolCallBlocks,
    });

    for (const tc of toolCallBlocks) {
      if (tc.type !== 'function') continue;
      const name = tc.function.name;
      let parsedArgs: unknown = {};
      try {
        parsedArgs = JSON.parse(tc.function.arguments || '{}');
      } catch (err) {
        log.warn(
          `Tool ${name}: failed to parse arguments JSON (${err instanceof Error ? err.message : String(err)})`,
        );
      }

      try {
        const result = await opts.registry.dispatch(
          name,
          parsedArgs,
          opts.ctx,
        );
        lastToolName = name;
        lastToolOutput = result;
        toolCalls.push({
          name,
          ok: true,
          input: parsedArgs,
          output: result,
        });
        messages.push({
          role: 'tool',
          tool_call_id: tc.id,
          content: JSON.stringify(result),
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        log.warn(`Tool ${name} threw: ${message}`);
        toolCalls.push({
          name,
          ok: false,
          input: parsedArgs,
          error: message,
        });
        messages.push({
          role: 'tool',
          tool_call_id: tc.id,
          content: `Tool error: ${message}`,
        });
      }
    }
  }

  log.warn(
    `OpenAI tool-use loop hit MAX_LOOP_ITERATIONS=${MAX_LOOP_ITERATIONS} without resolving.`,
  );
  return {
    text:
      "I'm taking too long to work this out — please try a more specific question.",
    lastToolName,
    lastToolOutput,
    toolCalls,
    tokensIn,
    tokensOut,
  };
}
