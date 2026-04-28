import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  BedrockRuntimeClient,
  ConverseCommand,
  type ContentBlock,
  type ConverseCommandOutput,
  type Message as BedrockMessage,
  type SystemContentBlock,
  type Tool as BedrockTool,
  type ToolChoice as BedrockToolChoice,
} from '@aws-sdk/client-bedrock-runtime';
import type { DocumentType } from '@smithy/types';
import { randomUUID } from 'crypto';
import type { LlmProvider } from './llm-provider.interface';
import type {
  LlmAssistantMessage,
  LlmFinishReason,
  LlmGenerateOptions,
  LlmGenerateResult,
  LlmMessage,
  LlmTool,
  LlmToolCall,
  LlmToolChoice,
} from './llm.types';

const DEFAULT_MODEL_ID = 'meta.llama3-3-70b-instruct-v1:0';
const JSON_MODE_INSTRUCTION = 'You MUST respond with a single valid JSON object only. No prose, no code fences, no commentary before or after the JSON.';

@Injectable()
export class BedrockLlmProvider implements LlmProvider {
  readonly name = 'bedrock' as const;
  private readonly logger = new Logger(BedrockLlmProvider.name);
  private readonly client: BedrockRuntimeClient;
  private readonly modelId: string;

  constructor(private readonly configService: ConfigService) {
    const region = this.configService.get<string>('llm.bedrock.region') || process.env.AWS_REGION
    this.modelId = this.configService.get<string>('llm.bedrock.modelId') || DEFAULT_MODEL_ID;
    this.client = new BedrockRuntimeClient({ region });
  }

  async generate(options: LlmGenerateOptions): Promise<LlmGenerateResult> {
    const { system, messages } = splitSystemAndConversation(
      options.messages,
      options.responseFormat === 'json_object',
    );

    const toolConfig =
      options.tools?.length && options.toolChoice !== 'none'
        ? {
            tools: options.tools.map(toBedrockTool),
            toolChoice: mapToolChoice(options.toolChoice),
          }
        : undefined;

    const command = new ConverseCommand({
      modelId: options.model ?? this.modelId,
      system,
      messages,
      toolConfig,
      inferenceConfig: {
        temperature: options.temperature,
        maxTokens: options.maxTokens,
      },
    });

    const response = await this.client.send(command);
    return normalizeResponse(response);
  }
}

interface BedrockSplitResult {
  system: SystemContentBlock[];
  messages: BedrockMessage[];
}

function splitSystemAndConversation(
  messages: LlmMessage[],
  jsonMode: boolean,
): BedrockSplitResult {
  const system: SystemContentBlock[] = [];
  const out: BedrockMessage[] = [];

  for (const m of messages) {
    if (m.role === 'system') {
      if (m.content) system.push({ text: m.content });
      continue;
    }
    if (m.role === 'user') {
      out.push({ role: 'user', content: [{ text: m.content }] });
      continue;
    }
    if (m.role === 'assistant') {
      const blocks: ContentBlock[] = [];
      if (m.content && m.content.trim().length > 0) {
        blocks.push({ text: m.content });
      }
      if (m.toolCalls?.length) {
        for (const tc of m.toolCalls) {
          blocks.push({
            toolUse: {
              toolUseId: tc.id,
              name: tc.name,
              input: parseArguments(tc.arguments),
            },
          });
        }
      }

      if (blocks.length === 0) continue;
      out.push({ role: 'assistant', content: blocks });
      continue;
    }
    if (m.role === 'tool') {
      const lastIsToolResultUser =
        out.length > 0 &&
        out[out.length - 1].role === 'user' &&
        Array.isArray(out[out.length - 1].content) &&
        out[out.length - 1].content!.every((b) => 'toolResult' in b);
      const block: ContentBlock = {
        toolResult: {
          toolUseId: m.toolCallId,
          content: [{ text: m.content }],
        },
      };
      if (lastIsToolResultUser) {
        out[out.length - 1].content!.push(block);
      } else {
        out.push({ role: 'user', content: [block] });
      }
      continue;
    }
  }

  if (jsonMode) system.push({ text: JSON_MODE_INSTRUCTION });
  return { system, messages: out };
}

function toBedrockTool(t: LlmTool): BedrockTool {
  return {
    toolSpec: {
      name: t.name,
      description: t.description,
      inputSchema: { json: t.parameters as DocumentType },
    },
  };
}

function mapToolChoice(c?: LlmToolChoice): BedrockToolChoice | undefined {
  if (!c || c === 'auto') return { auto: {} };
  if (c === 'required') return { any: {} };
  return undefined;
}

function parseArguments(raw: string): DocumentType {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as DocumentType) : {};
  } catch {
    return {};
  }
}

function normalizeResponse(response: ConverseCommandOutput): LlmGenerateResult {
  const blocks = response.output?.message?.content ?? [];
  let text = '';
  const toolCalls: LlmToolCall[] = [];

  for (const block of blocks) {
    if ('text' in block && typeof block.text === 'string') {
      text += block.text;
    } else if ('toolUse' in block && block.toolUse) {
      toolCalls.push({
        id: block.toolUse.toolUseId ?? randomUUID(),
        name: block.toolUse.name ?? '',
        arguments: JSON.stringify(block.toolUse.input ?? {}),
      });
    }
  }

  if (toolCalls.length === 0 && text) {
    const recovered = extractTextEncodedToolCalls(text);
    if (recovered.calls.length > 0) {
      toolCalls.push(...recovered.calls);
      text = recovered.remainder;
    }
  }

  const message: LlmAssistantMessage = {
    role: 'assistant',
    content: text.length > 0 ? text : null,
  };
  if (toolCalls.length) message.toolCalls = toolCalls;

  let finishReason = mapStopReason(response.stopReason);
  if (toolCalls.length > 0 && finishReason === 'stop') {
    finishReason = 'tool_calls';
  }

  return {
    message,
    finishReason,
    usage: response.usage
      ? {
          promptTokens: response.usage.inputTokens ?? 0,
          completionTokens: response.usage.outputTokens ?? 0,
          totalTokens: response.usage.totalTokens ?? 0,
        }
      : undefined,
    raw: response,
  };
}

/**
 * Detect text that contains one or more Llama-style JSON tool calls and lift
 * them into LlmToolCall entries. Recognized shapes (most common first):
 *   {"type":"function","name":"X","parameters":{...}}
 *   {"name":"X","parameters":{...}}
 *   {"name":"X","arguments":{...}}
 * Optionally wrapped in ```json … ``` fences. Multiple objects in the same
 * content (separated by whitespace or newlines) are all extracted.
 */
function extractTextEncodedToolCalls(text: string): {
  calls: LlmToolCall[];
  remainder: string;
} {
  const calls: LlmToolCall[] = [];
  let s = text.trim();

  const fenceMatch = s.match(/^```(?:json|tool|tool_call|tool_use)?\s*\n?([\s\S]*?)\n?```$/);
  if (fenceMatch) s = fenceMatch[1].trim();

  // Walk the string finding balanced JSON objects starting at '{'.
  let i = 0;
  let preamble = '';
  while (i < s.length) {
    const start = s.indexOf('{', i);
    if (start < 0) {
      preamble += s.slice(i);
      break;
    }
    preamble += s.slice(i, start);

    const end = findMatchingBrace(s, start);
    if (end < 0) {
      preamble += s.slice(start);
      break;
    }

    const candidate = s.slice(start, end + 1);
    const parsed = parseToolCallObject(candidate);
    if (parsed) {
      calls.push(parsed);
      i = end + 1;
      continue;
    }
    // Not a tool call shape — keep it as text and move past this brace.
    preamble += candidate;
    i = end + 1;
  }

  return {
    calls,
    remainder: calls.length > 0 ? preamble.trim() : text,
  };
}

function findMatchingBrace(s: string, openIdx: number): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = openIdx; i < s.length; i++) {
    const ch = s[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (inString) {
      if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function parseToolCallObject(json: string): LlmToolCall | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const obj = parsed as Record<string, unknown>;
  const name = typeof obj.name === 'string' ? obj.name.trim() : null;
  if (!name) return null;
  const args =
    (obj.parameters && typeof obj.parameters === 'object' && obj.parameters) ||
    (obj.arguments && typeof obj.arguments === 'object' && obj.arguments) ||
    {};
  return {
    id: randomUUID(),
    name,
    arguments: JSON.stringify(args),
  };
}

function mapStopReason(reason: string | undefined): LlmFinishReason {
  switch (reason) {
    case 'end_turn':
    case 'stop_sequence':
      return 'stop';
    case 'tool_use':
      return 'tool_calls';
    case 'max_tokens':
      return 'length';
    case 'content_filtered':
      return 'content_filter';
    default:
      return 'other';
  }
}
