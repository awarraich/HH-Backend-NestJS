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

/**
 * Coerce a tool-call argument to a bounded positive integer with a fallback.
 * Models sometimes pass numeric arguments as strings ("50"), as alphabetic
 * placeholders ("all"), as floats, or out of range. Defensive coercion at
 * every tool entry prevents one bad token from crashing TypeORM downstream.
 */
export function toBoundedInt(
  value: unknown,
  opts: { fallback: number; min?: number; max?: number },
): number {
  const min = opts.min ?? 1;
  const max = opts.max ?? Number.MAX_SAFE_INTEGER;
  const n =
    typeof value === 'number'
      ? value
      : typeof value === 'string'
        ? Number(value.trim())
        : NaN;
  if (!Number.isFinite(n)) return opts.fallback;
  const floored = Math.floor(n);
  if (floored < min) return opts.fallback;
  if (floored > max) return max;
  return floored;
}
