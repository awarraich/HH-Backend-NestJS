import { z } from 'zod';
import type { EmployeeShiftService } from '../../../organizations/scheduling/services/employee-shift.service';
import type { Tool } from '../tool.types';
import { resolveRange } from './date-range';
import { AvailableShiftOutput, DateRangeInput } from './shift.schemas';

const ListAvailableShiftsInput = DateRangeInput;
const ListAvailableShiftsOutput = z.object({
  shifts: z.array(AvailableShiftOutput),
  range: z.object({ from: z.string(), to: z.string() }),
  note: z.string(),
});

type Input = z.infer<typeof ListAvailableShiftsInput>;
type Output = z.infer<typeof ListAvailableShiftsOutput>;

export function buildListAvailableShiftsTool(
  employeeShifts: EmployeeShiftService,
): Tool<Input, Output> {
  return {
    name: 'listAvailableShifts',
    description:
      "Returns active shifts in the caller's organization that match the caller's role qualifications " +
      "(or have no role requirement). This is informational only — the bot CANNOT self-assign the caller; " +
      "shift assignment is a managerial decision. Defaults to today through 7 days from now.",
    input: ListAvailableShiftsInput,
    output: ListAvailableShiftsOutput,
    handler: async (input, ctx) => {
      const range = resolveRange(input);
      const shifts = await employeeShifts.findAvailableForCallerSelf(
        ctx.user.organizationId,
        ctx.user.userId,
        range,
      );
      return {
        shifts: shifts.map((s) => ({
          id: s.id,
          name: s.name,
          shiftType: s.shift_type,
          startAt: s.start_at.toISOString(),
          endAt: s.end_at.toISOString(),
          recurrenceType: s.recurrence_type,
          requiredRoles: (s.shiftRoles ?? []).map(
            (sr) => sr.providerRole?.code ?? sr.provider_role_id,
          ),
        })),
        range,
        note: 'These are role-qualified shifts only. Talk to your manager about being assigned to one.',
      };
    },
  };
}
