export type LlmMessageRole = 'system' | 'user' | 'assistant' | 'tool';

export interface LlmSystemMessage {
  role: 'system';
  content: string;
}

export interface LlmUserMessage {
  role: 'user';
  content: string;
}

export interface LlmAssistantMessage {
  role: 'assistant';
  content: string | null;
  toolCalls?: LlmToolCall[];
}

export interface LlmToolMessage {
  role: 'tool';
  toolCallId: string;
  content: string;
}

export type LlmMessage =
  | LlmSystemMessage
  | LlmUserMessage
  | LlmAssistantMessage
  | LlmToolMessage;

export interface LlmToolCall {
  id: string;
  name: string;
  // JSON-encoded argument string, matching the OpenAI wire format. Providers
  // that return structured arguments (Bedrock Converse) stringify on the way out
  // so callers' JSON.parse paths stay unchanged.
  arguments: string;
}

export interface LlmTool {
  name: string;
  description?: string;
  parameters: Record<string, unknown>;
}

export type LlmToolChoice = 'auto' | 'required' | 'none';

export type LlmResponseFormat = 'text' | 'json_object';

export interface LlmGenerateOptions {
  messages: LlmMessage[];
  tools?: LlmTool[];
  toolChoice?: LlmToolChoice;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  responseFormat?: LlmResponseFormat;
}

export type LlmFinishReason =
  | 'stop'
  | 'tool_calls'
  | 'length'
  | 'content_filter'
  | 'other';

export interface LlmUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface LlmGenerateResult {
  message: LlmAssistantMessage;
  finishReason: LlmFinishReason;
  usage?: LlmUsage;
  raw?: unknown;
}
