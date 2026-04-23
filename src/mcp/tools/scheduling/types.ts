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
  /**
   * IANA timezone identifier (e.g. "America/Los_Angeles", "America/New_York")
   * supplied per-request by the client. Used to render timestamps in local
   * time everywhere shift data crosses the LLM boundary. Falls back to
   * "America/Los_Angeles" (US Pacific).
   */
  timezone: string;
  /**
   * UUIDs of the department/station/room/bed/chair the user is currently
   * looking at on the frontend. When the assignment tool is called without
   * these fields, the handler auto-fills them so assignments land in the
   * right grid cell rather than at the org root with NULL location.
   */
  departmentId?: string;
  stationId?: string;
  roomId?: string;
  bedId?: string;
  chairId?: string;
}

export function jsonResult(data: unknown): {
  content: Array<{ type: 'text'; text: string }>;
} {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
  };
}
