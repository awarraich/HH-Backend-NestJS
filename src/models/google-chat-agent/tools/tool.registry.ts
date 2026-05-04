import { Injectable, Logger } from '@nestjs/common';
import { zodToJsonSchema } from 'zod-to-json-schema';
import {
  AnthropicToolPayload,
  AnyTool,
  AgentContext,
  DuplicateToolError,
  OpenAIToolPayload,
  Tool,
  ToolInputValidationError,
  ToolNotFoundError,
  ToolOutputValidationError,
} from './tool.types';

/**
 * Central registry of agent tools.
 *
 * Responsibilities:
 *   1. Hold the canonical tool list — duplicate names rejected at registration.
 *   2. Produce the Anthropic SDK `tools` payload, with prompt-cache breakpoint
 *      on the last entry so the tools block stays in cache across turns.
 *   3. Dispatch a tool call: validate input via Zod, run the handler, validate
 *      output via Zod, surface structured errors at every step.
 *
 * Integration / RBAC / transcripts / quota are NOT this class's concern.
 * Wrappers in M10 (RBAC), M11 (transcript), M14 (quota) compose around dispatch.
 */
@Injectable()
export class ToolRegistry {
  private readonly logger = new Logger(ToolRegistry.name);
  private readonly tools = new Map<string, AnyTool>();

  register<I, O>(tool: Tool<I, O>): void {
    if (this.tools.has(tool.name)) {
      throw new DuplicateToolError(tool.name);
    }
    this.tools.set(tool.name, tool as unknown as AnyTool);
    this.logger.log(`Registered tool: ${tool.name}`);
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  list(): string[] {
    return Array.from(this.tools.keys());
  }

  size(): number {
    return this.tools.size;
  }

  /**
   * Build the Anthropic SDK tools payload. The LAST tool in the array
   * carries `cache_control: { type: 'ephemeral' }` so Anthropic caches
   * the entire tools block (system prompt cache breakpoint applied
   * separately at message construction).
   */
  getAnthropicToolsPayload(): AnthropicToolPayload[] {
    const entries = Array.from(this.tools.values());
    return entries.map((tool, idx) => {
      const jsonSchema = zodToJsonSchema(tool.input, {
        target: 'jsonSchema7',
        $refStrategy: 'none',
      }) as Record<string, unknown>;

      // Anthropic's SDK doesn't want the $schema or definitions metadata,
      // and requires `type: "object"` at the top level.
      const { $schema, definitions, ...rest } = jsonSchema as {
        $schema?: unknown;
        definitions?: unknown;
        type?: unknown;
        properties?: Record<string, unknown>;
        required?: string[];
        additionalProperties?: boolean;
      };
      void $schema;
      void definitions;

      const payload: AnthropicToolPayload = {
        name: tool.name,
        description: tool.description,
        input_schema: {
          type: 'object',
          properties:
            (rest as { properties?: Record<string, unknown> }).properties ?? {},
          required: (rest as { required?: string[] }).required,
          additionalProperties:
            (rest as { additionalProperties?: boolean }).additionalProperties ??
            false,
        },
      };

      if (idx === entries.length - 1) {
        payload.cache_control = { type: 'ephemeral' };
      }
      return payload;
    });
  }

  /**
   * Build the OpenAI Chat Completions tools payload. OpenAI uses an outer
   * wrapper `{ type: 'function', function: {...} }` and embeds the JSON
   * Schema as `parameters`. No cache_control needed — OpenAI does
   * prompt-prefix caching automatically server-side for prefixes
   * over ~1024 tokens (since 2024-08).
   */
  getOpenAIToolsPayload(): OpenAIToolPayload[] {
    const entries = Array.from(this.tools.values());
    return entries.map((tool) => {
      const jsonSchema = zodToJsonSchema(tool.input, {
        target: 'jsonSchema7',
        $refStrategy: 'none',
      }) as Record<string, unknown>;

      const { $schema, definitions, ...rest } = jsonSchema as {
        $schema?: unknown;
        definitions?: unknown;
        properties?: Record<string, unknown>;
        required?: string[];
        additionalProperties?: boolean;
      };
      void $schema;
      void definitions;

      return {
        type: 'function',
        function: {
          name: tool.name,
          description: tool.description,
          parameters: {
            type: 'object',
            properties:
              (rest as { properties?: Record<string, unknown> }).properties ??
              {},
            required: (rest as { required?: string[] }).required,
            additionalProperties:
              (rest as { additionalProperties?: boolean })
                .additionalProperties ?? false,
          },
          strict: false,
        },
      };
    });
  }

  /**
   * Run a tool by name. Validates input → calls handler → validates output.
   *
   * Throws:
   *   - ToolNotFoundError       — name not registered
   *   - ToolInputValidationError — model produced bad input
   *   - ToolOutputValidationError — handler produced output that doesn't
   *                                 match its declared schema (a bug in the
   *                                 tool, not in user input)
   *   - any error thrown by the handler itself (propagated as-is)
   */
  async dispatch(
    name: string,
    input: unknown,
    ctx: AgentContext,
  ): Promise<unknown> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new ToolNotFoundError(name);
    }

    const inputResult = tool.input.safeParse(input);
    if (!inputResult.success) {
      throw new ToolInputValidationError(name, inputResult.error.issues);
    }

    const result = await tool.handler(inputResult.data, ctx);

    const outputResult = tool.output.safeParse(result);
    if (!outputResult.success) {
      throw new ToolOutputValidationError(name, outputResult.error.issues);
    }
    return outputResult.data;
  }
}
