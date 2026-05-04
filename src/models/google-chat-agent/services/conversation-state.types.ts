/**
 * One turn in a Google Chat agent conversation.
 *
 * `content` is left typed as `unknown` so we can store the Anthropic SDK's
 * `MessageParam` shape verbatim (which itself is a discriminated union of
 * text blocks, tool_use blocks, tool_result blocks, etc.) without coupling
 * this type to the SDK's evolving generics.
 */
export interface AgentTurn {
  role: 'user' | 'assistant' | 'tool';
  content: unknown;
  ts: string; // ISO timestamp
}

/** Maximum number of turns retained per Chat thread. */
export const MAX_TURNS = 12;

/** TTL since last turn — 30 minutes. */
export const CONVERSATION_TTL_MS = 30 * 60 * 1000;
