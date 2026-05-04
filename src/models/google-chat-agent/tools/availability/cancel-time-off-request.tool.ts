import { z } from 'zod';
import type { TimeOffRequestService } from '../../../employees/availability/services/time-off-request.service';
import type { Tool } from '../tool.types';
import {
  TimeOffRequestOutput,
  normalizeTimeOffStatus,
} from './availability.schemas';

const Input = z.object({
  requestId: z
    .string()
    .uuid()
    .describe('UUID of the time-off request to cancel'),
});

const Output = z.object({
  request: TimeOffRequestOutput,
  message: z.string(),
});

type In = z.infer<typeof Input>;
type Out = z.infer<typeof Output>;

export function buildCancelTimeOffRequestTool(
  service: TimeOffRequestService,
): Tool<In, Out> {
  return {
    name: 'cancelTimeOffRequest',
    description:
      "Cancels one of the calling employee's own pending time-off requests. " +
      "Only PENDING requests can be cancelled — approved/denied/already-cancelled ones throw. " +
      "Cannot cancel another employee's requests (the underlying service throws NotFound " +
      "if the request doesn't belong to the caller).",
    input: Input,
    output: Output,
    handler: async (input, ctx) => {
      const cancelled = await service.cancel(
        ctx.user.userId,
        input.requestId,
      );
      return {
        request: {
          id: cancelled.id,
          startDate: cancelled.start_date,
          endDate: cancelled.end_date,
          reason: cancelled.reason,
          // The service deletes the row on cancel, but we report 'cancelled'
          // upstream so the model and renderer can reason about the outcome.
          status: 'cancelled',
          reviewNotes: cancelled.review_notes,
          createdAt: cancelled.created_at.toISOString(),
        },
        message: `Cancelled time-off request for ${cancelled.start_date} → ${cancelled.end_date}.`,
      };
    },
  };
}
