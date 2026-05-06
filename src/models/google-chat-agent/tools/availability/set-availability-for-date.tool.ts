import { z } from 'zod';
import type { AvailabilityRuleService } from '../../../employees/availability/services/availability-rule.service';
import type { Tool } from '../tool.types';
import {
  AvailabilityRuleOutput,
  DateOnly,
  TimeOnly,
} from './availability.schemas';

const Input = z.object({
  date: DateOnly.describe(
    'Specific date to set availability for (YYYY-MM-DD). The day-of-week is derived from this date — do NOT pass it separately.',
  ),
  startTime: TimeOnly,
  endTime: TimeOnly,
  isAvailable: z
    .boolean()
    .optional()
    .describe('false = unavailable on that date in that window; defaults to true'),
  shiftType: z
    .string()
    .max(50)
    .nullable()
    .optional()
    .describe('Optional label like "morning", "evening"'),
});

const Output = z.object({
  rule: AvailabilityRuleOutput,
  message: z.string(),
});

type In = z.infer<typeof Input>;
type Out = z.infer<typeof Output>;

function todayUtc(): string {
  return new Date().toISOString().slice(0, 10);
}

export function buildSetAvailabilityForDateTool(
  rulesService: AvailabilityRuleService,
): Tool<In, Out> {
  return {
    name: 'setAvailabilityForDate',
    description:
      "Sets the calling employee's availability for a SINGLE specific calendar date. " +
      "Use this when the user says 'on May 8 I'm available 7am-3pm' or names any specific date. " +
      "REPLACES any prior date-specific overrides for that date in the same organization scope. " +
      "Does NOT change recurring weekly rules. The day-of-week is derived from the date so the " +
      "model never has to compute weekday arithmetic.",
    input: Input,
    output: Output,
    handler: async (input, ctx) => {
      if (input.date < todayUtc()) {
        throw new Error(
          'Cannot set availability for a date that has already passed.',
        );
      }
      if (input.startTime === input.endTime) {
        throw new Error('startTime and endTime cannot be equal.');
      }

      const saved = await rulesService.upsertDateOverride(
        ctx.user.userId,
        input.date,
        {
          organization_id: ctx.user.organizationId,
          rules: [
            {
              start_time: input.startTime,
              end_time: input.endTime,
              is_available: input.isAvailable ?? true,
              shift_type: input.shiftType ?? undefined,
            },
          ],
        },
      );

      // upsertDateOverride returns an array (it supports multiple slots per date,
      // but we always send exactly one). Defensive: if empty, throw — that means
      // the underlying service silently dropped our rule.
      const rule = saved[0];
      if (!rule) {
        throw new Error(
          'Availability override was not saved. Try again or contact support.',
        );
      }

      const verb = (input.isAvailable ?? true) ? 'available' : 'unavailable';
      return {
        rule: {
          id: rule.id,
          dayOfWeek: rule.day_of_week,
          date: rule.date,
          startTime: rule.start_time,
          endTime: rule.end_time,
          isAvailable: rule.is_available,
          shiftType: rule.shift_type,
          effectiveFrom: rule.effective_from
            ? new Date(rule.effective_from).toISOString().slice(0, 10)
            : null,
          effectiveUntil: rule.effective_until
            ? new Date(rule.effective_until).toISOString().slice(0, 10)
            : null,
        },
        message: `Saved: ${verb} on ${input.date} from ${input.startTime} to ${input.endTime}.`,
      };
    },
  };
}
