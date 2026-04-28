import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import OpenAI from 'openai';
import type {
  ChatCompletionMessageParam,
  ChatCompletionTool,
  ChatCompletionToolChoiceOption,
} from 'openai/resources/chat/completions';
import type { LlmProvider } from './llm-provider.interface';
import type {
  LlmAssistantMessage,
  LlmFinishReason,
  LlmGenerateOptions,
  LlmGenerateResult,
  LlmMessage,
  LlmTool,
  LlmToolChoice,
} from './llm.types';

@Injectable()
export class OpenAiLlmProvider implements LlmProvider {
  readonly name = 'openai' as const;
  private readonly logger = new Logger(OpenAiLlmProvider.name);
  private readonly client: OpenAI;
  private readonly defaultModel: string;

  constructor(private readonly configService: ConfigService) {
    const apiKey =
      this.configService.get<string>('apiKeys.openai')?.trim() ||
      process.env.OPENAI_API_KEY?.trim() ||
      '';
    if (!apiKey) {
      this.logger.warn(
        'OPENAI_API_KEY is not set — OpenAI LLM calls will fail at runtime.',
      );
    }
    this.client = new OpenAI({ apiKey });
    this.defaultModel =
      this.configService.get<string>('llm.openai.model') ?? 'gpt-4o';
  }

  async generate(options: LlmGenerateOptions): Promise<LlmGenerateResult> {
    const messages = options.messages.map(toOpenAiMessage);
    const tools = options.tools?.length ? options.tools.map(toOpenAiTool) : undefined;
    const toolChoice = mapToolChoice(options.toolChoice);

    const completion = await this.client.chat.completions.create({
      model: options.model ?? this.defaultModel,
      messages,
      tools,
      tool_choice: toolChoice,
      temperature: options.temperature,
      max_tokens: options.maxTokens,
      response_format:
        options.responseFormat === 'json_object'
          ? { type: 'json_object' }
          : undefined,
    });

    const choice = completion.choices?.[0];
    const raw = choice?.message;
    const message: LlmAssistantMessage = {
      role: 'assistant',
      content: raw?.content ?? null,
      toolCalls: raw?.tool_calls
        ?.filter((tc) => tc.type === 'function')
        .map((tc) => ({
          id: tc.id,
          name: tc.function.name,
          arguments: tc.function.arguments ?? '',
        })),
    };
    if (message.toolCalls && message.toolCalls.length === 0) {
      delete message.toolCalls;
    }

    return {
      message,
      finishReason: mapFinishReason(choice?.finish_reason),
      usage: completion.usage
        ? {
            promptTokens: completion.usage.prompt_tokens,
            completionTokens: completion.usage.completion_tokens,
            totalTokens: completion.usage.total_tokens,
          }
        : undefined,
      raw: completion,
    };
  }
}

function toOpenAiMessage(m: LlmMessage): ChatCompletionMessageParam {
  switch (m.role) {
    case 'system':
      return { role: 'system', content: m.content };
    case 'user':
      return { role: 'user', content: m.content };
    case 'assistant':
      return {
        role: 'assistant',
        content: m.content,
        tool_calls: m.toolCalls?.map((tc) => ({
          id: tc.id,
          type: 'function',
          function: { name: tc.name, arguments: tc.arguments },
        })),
      };
    case 'tool':
      return { role: 'tool', tool_call_id: m.toolCallId, content: m.content };
  }
}

function toOpenAiTool(t: LlmTool): ChatCompletionTool {
  return {
    type: 'function',
    function: { name: t.name, description: t.description, parameters: t.parameters },
  };
}

function mapToolChoice(c?: LlmToolChoice): ChatCompletionToolChoiceOption | undefined {
  if (!c) return undefined;
  if (c === 'auto') return 'auto';
  if (c === 'none') return 'none';
  if (c === 'required') return 'required';
  return undefined;
}

function mapFinishReason(reason: string | null | undefined): LlmFinishReason {
  switch (reason) {
    case 'stop':
      return 'stop';
    case 'tool_calls':
    case 'function_call':
      return 'tool_calls';
    case 'length':
      return 'length';
    case 'content_filter':
      return 'content_filter';
    default:
      return 'other';
  }
}
