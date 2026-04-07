export type SchedulingToolResult = Promise<{
  content: Array<{ type: 'text'; text: string }>;
}>;

export interface SchedulingToolDescriptor {
  name: string;
  description: string;
  inputSchema: object;
  handler: (args: unknown) => SchedulingToolResult;
}

export interface SchedulingToolContext {
  organizationId: string;
  userId: string;
}

export function jsonResult(data: unknown): {
  content: Array<{ type: 'text'; text: string }>;
} {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
  };
}
