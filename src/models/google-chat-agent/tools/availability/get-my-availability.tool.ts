import { z } from 'zod';
import type { AvailabilityRuleService } from '../../../employees/availability/services/availability-rule.service';
import type { WorkPreferenceService } from '../../../employees/availability/services/work-preference.service';
import type { Tool } from '../tool.types';
import {
  AvailabilityRuleOutput,
  WorkPreferenceOutput,
} from './availability.schemas';

const Input = z.object({}).describe('No parameters — always returns the caller\'s availability');
const Output = z.object({
  rules: z.array(AvailabilityRuleOutput),
  workPreferences: WorkPreferenceOutput,
});

type In = z.infer<typeof Input>;
type Out = z.infer<typeof Output>;

export function buildGetMyAvailabilityTool(
  rulesService: AvailabilityRuleService,
  prefsService: WorkPreferenceService,
): Tool<In, Out> {
  return {
    name: 'getMyAvailability',
    description:
      "Returns the calling employee's active recurring availability rules plus work preferences " +
      "(weekly hour cap, preferred shift type, overtime/on-call flags). Caller-self only — never " +
      "returns another employee's data.",
    input: Input,
    output: Output,
    handler: async (_input, ctx) => {
      const rules = await rulesService.findByUser(
        ctx.user.userId,
        ctx.user.organizationId,
      );
      const prefs = await prefsService.findOrCreate(ctx.user.userId);

      return {
        rules: rules.map((r) => ({
          id: r.id,
          dayOfWeek: r.day_of_week,
          date: r.date,
          startTime: r.start_time,
          endTime: r.end_time,
          isAvailable: r.is_available,
          shiftType: r.shift_type,
          effectiveFrom: r.effective_from
            ? new Date(r.effective_from).toISOString().slice(0, 10)
            : null,
          effectiveUntil: r.effective_until
            ? new Date(r.effective_until).toISOString().slice(0, 10)
            : null,
        })),
        workPreferences: {
          maxHoursPerWeek: prefs.max_hours_per_week,
          preferredShiftType: prefs.preferred_shift_type,
          availableForOvertime: prefs.available_for_overtime,
          availableForOnCall: prefs.available_for_on_call,
          workType: prefs.work_type,
        },
      };
    },
  };
}
