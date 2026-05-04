import { z } from 'zod';
import type { EmployeeShift } from '../../../organizations/scheduling/entities/employee-shift.entity';
import type { EmployeeShiftService } from '../../../organizations/scheduling/services/employee-shift.service';
import type { Tool } from '../tool.types';
import { resolveRange } from './date-range';
import {
  AssignmentOutput,
  DateRangeInput,
} from './shift.schemas';

const ListMyShiftsInput = DateRangeInput;
const ListMyShiftsOutput = z.object({
  shifts: z.array(AssignmentOutput),
  range: z.object({ from: z.string(), to: z.string() }),
});

type Input = z.infer<typeof ListMyShiftsInput>;
type Output = z.infer<typeof ListMyShiftsOutput>;

export function buildListMyShiftsTool(
  employeeShifts: EmployeeShiftService,
): Tool<Input, Output> {
  return {
    name: 'listMyShifts',
    description:
      "Returns the calling employee's own assigned shifts in a date range. " +
      'Defaults to today through 7 days from now. Caller-self only — never returns other employees.',
    input: ListMyShiftsInput,
    output: ListMyShiftsOutput,
    handler: async (input, ctx) => {
      const range = resolveRange(input);
      const rows = await employeeShifts.findByCallerSelf(
        ctx.user.organizationId,
        ctx.user.userId,
        range,
      );
      return {
        shifts: rows.map(toAssignmentOutput),
        range,
      };
    },
  };
}

function toAssignmentOutput(es: EmployeeShift): z.infer<typeof AssignmentOutput> {
  return {
    id: es.id,
    shiftId: es.shift_id,
    shiftName: es.shift?.name ?? null,
    scheduledDate: es.scheduled_date,
    startAt: es.shift?.start_at?.toISOString() ?? '',
    endAt: es.shift?.end_at?.toISOString() ?? '',
    status: es.status,
    role: es.role,
    location: {
      department: es.department?.name ?? null,
      station: es.station?.name ?? null,
      room: es.room?.name ?? null,
      bed: (es.bed as { name?: string | null } | null)?.name ?? null,
      chair: (es.chair as { name?: string | null } | null)?.name ?? null,
    },
    notes: es.notes,
  };
}

export const __test__ = { toAssignmentOutput };
