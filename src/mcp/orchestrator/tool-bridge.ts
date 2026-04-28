import { z, ZodRawShape } from 'zod';
import { zodToJsonSchema } from 'zod-to-json-schema';
import type { SchedulingToolDescriptor } from '../tools/scheduling';
import type { LlmTool } from '../../common/services/llm';


export function toLlmTools(descriptors: SchedulingToolDescriptor[]): LlmTool[] {
  return descriptors.map((d) => {
    const shape = d.inputSchema as ZodRawShape;
    const jsonSchema = zodToJsonSchema(z.object(shape), {
      target: 'openAi',
      $refStrategy: 'none',
    }) as Record<string, unknown>;

    delete jsonSchema.$schema;

    return {
      name: d.name,
      description: d.description,
      parameters: jsonSchema,
    };
  });
}
