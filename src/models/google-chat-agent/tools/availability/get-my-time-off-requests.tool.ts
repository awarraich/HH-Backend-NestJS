import { z } from 'zod';
import type { TimeOffRequestService } from '../../../employees/availability/services/time-off-request.service';
import type { Tool } from '../tool.types';
import {
  DateOnly,
  TimeOffRequestOutput,
  normalizeTimeOffStatus,
} from './availability.schemas';

const Input = z.object({
  status: z
    .enum(['pending', 'approved', 'denied', 'cancelled'])
    .optional()
    .describe('Filter by status — omit to get all'),
  fromDate: DateOnly.optional().describe(
    'Start of the date range; defaults to 30 days ago',
  ),
  toDate: DateOnly.optional().describe(
    'End of the date range; defaults to 60 days from now',
  ),
});

const Output = z.object({
  requests: z.array(TimeOffRequestOutput),
  range: z.object({ from: z.string(), to: z.string() }),
});

type In = z.infer<typeof Input>;
type Out = z.infer<typeof Output>;

function defaultRange() {
  const now = new Date();
  const past = new Date(now);
  past.setUTCDate(past.getUTCDate() - 30);
  past.setUTCHours(0, 0, 0, 0);
  const future = new Date(now);
  future.setUTCDate(future.getUTCDate() + 60);
  future.setUTCHours(23, 59, 59, 999);
  const yyyyMmDd = (d: Date) => d.toISOString().slice(0, 10);
  return { from: yyyyMmDd(past), to: yyyyMmDd(future) };
}

export function buildGetMyTimeOffRequestsTool(
  service: TimeOffRequestService,
): Tool<In, Out> {
  return {
    name: 'getMyTimeOffRequests',
    description:
      "Returns the calling employee's own time-off requests (default: last 30 / next 60 days). " +
      "Optionally filtered by status. Never returns another employee's requests.",
    input: Input,
    output: Output,
    handler: async (input, ctx) => {
      const def = defaultRange();
      const range = {
        from: input.fromDate ?? def.from,
        to: input.toDate ?? def.to,
      };

      const result = await service.findAll(ctx.user.userId, {
        organization_id: ctx.user.organizationId,
        status: input.status,
        from_date: range.from,
        to_date: range.to,
        page: 1,
        limit: 100,
      });

      return {
        requests: result.data.map((r) => ({
          id: r.id,
          startDate: r.start_date,
          endDate: r.end_date,
          reason: r.reason,
          status: normalizeTimeOffStatus(r.status),
          reviewNotes: r.review_notes,
          createdAt: r.created_at.toISOString(),
        })),
        range,
      };
    },
  };
}
