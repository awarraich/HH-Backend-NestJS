import { z } from 'zod';
import type { EmployeeShiftService } from '../../../organizations/scheduling/services/employee-shift.service';
import type { Tool } from '../tool.types';
import { AssignmentOutput } from './shift.schemas';

const GetShiftDetailsInput = z.object({
  shiftId: z
    .string()
    .uuid()
    .describe('The Shift template id (UUID) the caller wants details for'),
});

const GetShiftDetailsOutput = z.object({
  found: z.boolean(),
  message: z.string().optional(),
  shift: z
    .object({
      id: z.string(),
      name: z.string().nullable(),
      shiftType: z.string().nullable(),
      startAt: z.string(),
      endAt: z.string(),
      recurrenceType: z.string(),
      requiredRoles: z.array(z.string()),
    })
    .optional(),
  myAssignments: z.array(AssignmentOutput).optional(),
});

type Input = z.infer<typeof GetShiftDetailsInput>;
type Output = z.infer<typeof GetShiftDetailsOutput>;

export function buildGetShiftDetailsTool(
  employeeShifts: EmployeeShiftService,
): Tool<Input, Output> {
  return {
    name: 'getShiftDetails',
    description:
      "Returns details of a single shift PLUS the caller's own assignments to it. " +
      "Returns found=false if the caller is not assigned to the shift, the shift " +
      "doesn't exist, or it belongs to a different organization. Never returns " +
      "another employee's assignments to the shift.",
    input: GetShiftDetailsInput,
    output: GetShiftDetailsOutput,
    handler: async (input, ctx) => {
      const result = await employeeShifts.findShiftDetailsForCallerSelf(
        ctx.user.organizationId,
        ctx.user.userId,
        input.shiftId,
      );
      if (!result) {
        return {
          found: false,
          message:
            "You are not assigned to that shift, or it doesn't exist in your organization.",
        };
      }
      const { shift, assignments } = result;
      return {
        found: true,
        shift: {
          id: shift.id,
          name: shift.name,
          shiftType: shift.shift_type,
          startAt: shift.start_at.toISOString(),
          endAt: shift.end_at.toISOString(),
          recurrenceType: shift.recurrence_type,
          requiredRoles: (shift.shiftRoles ?? []).map(
            (sr) => sr.providerRole?.code ?? sr.provider_role_id,
          ),
        },
        myAssignments: assignments.map((es) => ({
          id: es.id,
          shiftId: es.shift_id,
          shiftName: shift.name,
          scheduledDate: es.scheduled_date,
          startAt: shift.start_at.toISOString(),
          endAt: shift.end_at.toISOString(),
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
        })),
      };
    },
  };
}
