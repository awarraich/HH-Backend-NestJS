import { z } from 'zod';
import type { AvailabilityRuleService } from '../../../employees/availability/services/availability-rule.service';
import type { Tool } from '../tool.types';
import {
  AvailabilityRuleOutput,
  DayOfWeek,
  TimeOnly,
} from './availability.schemas';

const Input = z.object({
  dayOfWeek: DayOfWeek,
  startTime: TimeOnly,
  endTime: TimeOnly,
  isAvailable: z
    .boolean()
    .optional()
    .describe('false = unavailable on that day in that window; defaults to true'),
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

const DAY_NAMES = [
  'Sunday',
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
];

export function buildSetAvailabilityRuleTool(
  rulesService: AvailabilityRuleService,
): Tool<In, Out> {
  return {
    name: 'setAvailabilityRule',
    description:
      "Sets the calling employee's recurring weekly availability for a single day of week. " +
      "REPLACES all existing weekly slots for that day in the same organization scope. " +
      "Does not affect date-specific overrides. Use this for 'I'm available Tuesdays 9-5' style requests.",
    input: Input,
    output: Output,
    handler: async (input, ctx) => {
      const rule = await rulesService.upsertWeeklyRuleForUser(ctx.user.userId, {
        organization_id: ctx.user.organizationId,
        day_of_week: input.dayOfWeek,
        start_time: input.startTime,
        end_time: input.endTime,
        is_available: input.isAvailable ?? true,
        shift_type: input.shiftType ?? null,
      });

      const dayName = DAY_NAMES[input.dayOfWeek] ?? `day ${input.dayOfWeek}`;
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
          effectiveFrom: null,
          effectiveUntil: null,
        },
        message: `Saved: ${verb} on ${dayName}s from ${input.startTime} to ${input.endTime}.`,
      };
    },
  };
}
