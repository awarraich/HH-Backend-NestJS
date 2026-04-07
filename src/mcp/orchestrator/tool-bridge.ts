import { z, ZodRawShape } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import type { ChatCompletionTool } from 'openai/resources/chat/completions';
import type { SchedulingToolDescriptor } from '../tools/scheduling';

/**
 * Convert internal scheduling tool descriptors into the OpenAI
 * `tools` parameter shape (function-calling).
 *
 * Tool descriptors store their input schema as a `ZodRawShape` (a plain
 * object of zod fields). We wrap each in `z.object(...)` and convert to
 * JSON Schema for OpenAI.
 */
export function toOpenAiTools(descriptors: SchedulingToolDescriptor[]): ChatCompletionTool[] {
  return descriptors.map((d) => {
    const shape = d.inputSchema as ZodRawShape;
    const jsonSchema = zodToJsonSchema(z.object(shape), {
      target: 'openAi',
      $refStrategy: 'none',
    }) as Record<string, unknown>;

    // OpenAI rejects the top-level $schema key — strip it.
    delete jsonSchema.$schema;

    return {
      type: 'function',
      function: {
        name: d.name,
        description: d.description,
        parameters: jsonSchema,
      },
    };
  });
}
