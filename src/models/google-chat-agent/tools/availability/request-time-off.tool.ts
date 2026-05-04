import { z } from 'zod';
import type { TimeOffRequestService } from '../../../employees/availability/services/time-off-request.service';
import type { Tool } from '../tool.types';
import {
  DateOnly,
  TimeOffRequestOutput,
  normalizeTimeOffStatus,
} from './availability.schemas';

const Input = z.object({
  startDate: DateOnly.describe('First day off (YYYY-MM-DD), inclusive'),
  endDate: DateOnly.describe(
    'Last day off (YYYY-MM-DD), inclusive — same as startDate for one-day requests',
  ),
  reason: z
    .string()
    .max(500)
    .optional()
    .describe('Optional reason; kept short, will be visible to managers'),
});

const Output = z.object({
  request: TimeOffRequestOutput,
  message: z.string(),
});

type In = z.infer<typeof Input>;
type Out = z.infer<typeof Output>;

function todayUtc(): string {
  return new Date().toISOString().slice(0, 10);
}

export function buildRequestTimeOffTool(
  service: TimeOffRequestService,
): Tool<In, Out> {
  return {
    name: 'requestTimeOff',
    description:
      "Submits a time-off request for the calling employee. Creates a 'pending' request that " +
      "a manager will review. Backdated requests (start date in the past) are rejected. " +
      "If the caller already has a pending request for the same window, returns the existing one " +
      "instead of creating a duplicate.",
    input: Input,
    output: Output,
    handler: async (input, ctx) => {
      // Reject backdated requests at the tool layer (the underlying service
      // accepts them — useful for admin backfill via the web UI but not
      // appropriate for an employee-facing bot).
      if (input.startDate < todayUtc()) {
        throw new Error(
          'Cannot request time off for dates that have already passed.',
        );
      }
      if (input.endDate < input.startDate) {
        throw new Error('endDate must be on or after startDate.');
      }

      // Lightweight idempotency: if a pending request with the same dates
      // and reason already exists, surface it rather than creating a duplicate.
      const existing = await service.findAll(ctx.user.userId, {
        organization_id: ctx.user.organizationId,
        status: 'pending',
        from_date: input.startDate,
        to_date: input.endDate,
        page: 1,
        limit: 50,
      });
      const dup = existing.data.find(
        (r) =>
          r.start_date === input.startDate &&
          r.end_date === input.endDate &&
          (r.reason ?? '') === (input.reason ?? ''),
      );

      const request =
        dup ??
        (await service.create(ctx.user.userId, {
          organization_id: ctx.user.organizationId,
          start_date: input.startDate,
          end_date: input.endDate,
          reason: input.reason,
        }));

      return {
        request: {
          id: request.id,
          startDate: request.start_date,
          endDate: request.end_date,
          reason: request.reason,
          status: normalizeTimeOffStatus(request.status),
          reviewNotes: request.review_notes,
          createdAt: request.created_at.toISOString(),
        },
        message: dup
          ? `You already have a pending request for ${input.startDate} → ${input.endDate}. No duplicate was created.`
          : `Time-off request submitted for ${input.startDate} → ${input.endDate}. Your manager will review it.`,
      };
    },
  };
}
