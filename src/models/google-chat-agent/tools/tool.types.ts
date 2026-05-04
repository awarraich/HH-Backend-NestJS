import { z } from 'zod';
import type { ResolvedAgentUser } from '../services/agent-identity.types';

/**
 * Per-turn context every tool receives. The resolved user is the SOLE
 * source of "who is asking" — tools must filter by `ctx.user.userId` /
 * `ctx.user.organizationId` and never trust input parameters that
 * could specify a different user.
 *
 * `turnId` is a per-message correlation id used by transcript logging
 * (M11) and observability (M16).
 */
export interface AgentContext {
  user: ResolvedAgentUser;
  turnId: string;
}

/**
 * A single tool the agent can call. The shape is intentionally minimal:
 * one file declares the name, the description shown to the model, the
 * input/output schemas (as Zod), and the handler.
 *
 * The `requiredRoles` field intentionally does NOT exist on this type.
 * Per the agent's hard self-only scope (see plan §scope), there are no
 * role-gated tools in v1 — every tool runs as the calling employee, on
 * the calling employee's data. If that ever changes, that's a new module.
 */
export interface Tool<I, O> {
  name: string;
  description: string;
  input: z.ZodType<I>;
  output: z.ZodType<O>;
  handler: (input: I, ctx: AgentContext) => Promise<O>;
}

/** Convenience alias for tools whose input/output types are unknown to the registry. */
export type AnyTool = Tool<unknown, unknown>;

/** Thrown when dispatch is called with a name no tool was registered under. */
export class ToolNotFoundError extends Error {
  constructor(public readonly toolName: string) {
    super(`Tool not found: ${toolName}`);
    this.name = 'ToolNotFoundError';
  }
}

/** Thrown when input from the model fails the tool's Zod schema. */
export class ToolInputValidationError extends Error {
  constructor(
    public readonly toolName: string,
    public readonly issues: z.ZodIssue[],
  ) {
    super(
      `Invalid input for tool "${toolName}": ${issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
    );
    this.name = 'ToolInputValidationError';
  }
}

/**
 * Thrown when the handler returns data that fails its declared output
 * schema. This indicates a bug in the tool implementation — the model
 * should never see invalid output (so we throw before returning).
 */
export class ToolOutputValidationError extends Error {
  constructor(
    public readonly toolName: string,
    public readonly issues: z.ZodIssue[],
  ) {
    super(
      `Tool "${toolName}" produced invalid output: ${issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
    );
    this.name = 'ToolOutputValidationError';
  }
}

/** Thrown when registering a tool whose name is already taken. */
export class DuplicateToolError extends Error {
  constructor(public readonly toolName: string) {
    super(`A tool with name "${toolName}" is already registered.`);
    this.name = 'DuplicateToolError';
  }
}

/**
 * The Anthropic SDK's tool definition shape — narrowed to what we emit.
 * Kept as a local type rather than depending on the SDK's generic so the
 * registry remains decoupled from SDK version drift.
 */
export interface AnthropicToolPayload {
  name: string;
  description: string;
  input_schema: {
    type: 'object';
    properties?: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
  /** Set on the last tool in the payload to enable prompt caching of the tools block. */
  cache_control?: { type: 'ephemeral' };
}

/**
 * The OpenAI Chat Completions SDK's tool definition shape — narrowed to what
 * we emit. OpenAI does prompt caching automatically server-side for prefixes
 * over ~1024 tokens (since 2024-08), so no explicit cache_control needed.
 */
export interface OpenAIToolPayload {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: {
      type: 'object';
      properties?: Record<string, unknown>;
      required?: string[];
      additionalProperties?: boolean;
    };
    /** Strict mode: model must produce exactly the schema. Recommended on. */
    strict?: boolean;
  };
}
