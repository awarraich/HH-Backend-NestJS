import { z } from 'zod';
import type { EmployeeShiftService } from '../../../models/organizations/scheduling/services/employee-shift.service';
import type { EmployeeAvailabilityService } from '../../../models/organizations/scheduling/services/employee-availability.service';
import type { EmployeesService } from '../../../models/employees/services/employees.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
} from './types';
import { enrichShiftWithLocalTime } from './format-shift-times';

const WEEKDAY_CODES = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'] as const;

const assignSchema = {
  shift_id: z
    .string()
    .uuid()
    .describe('UUID of the existing Shift template (look up via search_shifts first).'),
  employee_id: z.string().uuid().describe('UUID of the employee to assign.'),
  scheduled_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .optional()
    .describe(
      'YYYY-MM-DD — the specific calendar date this assignment is for. ' +
      'REQUIRED for recurring shifts (FULL_WEEK, WEEKDAYS, etc.). ' +
      'For ONE_TIME shifts, omit this and it will be derived from the shift start_at.',
    ),
  department_id: z.string().uuid().optional(),
  station_id: z.string().uuid().optional(),
  room_id: z.string().uuid().optional(),
  bed_id: z.string().uuid().optional(),
  chair_id: z.string().uuid().optional(),
  status: z
    .string()
    .max(20)
    .optional()
    .describe('Default SCHEDULED. Other examples: CONFIRMED, CANCELLED.'),
  notes: z.string().optional(),
};

export function buildAssignmentTools(
  employeeShiftService: EmployeeShiftService,
  employeesService: EmployeesService,
  availabilityService: EmployeeAvailabilityService,
  ctx: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  const assignEmployeeToShift = async (args: {
    shift_id: string;
    employee_id: string;
    scheduled_date?: string;
    department_id?: string;
    station_id?: string;
    room_id?: string;
    bed_id?: string;
    chair_id?: string;
    status?: string;
    notes?: string;
  }): SchedulingToolResult => {
    try {
      // Reject scheduled_date values where the employee has no matching
      // availability rule. Without this guard, the agent can (and has)
      // pick a weekday the employee isn't available on — e.g. assigning a
      // Wednesday-only employee to Tuesday. We fail fast with a clear
      // error message so the agent can correct itself.
      if (args.scheduled_date) {
        const availability = await availabilityService.findAvailability({
          employeeId: args.employee_id,
          organizationId: ctx.organizationId,
          status: 'available',
        });
        if (availability.length > 0) {
          const weekday = WEEKDAY_CODES[
            new Date(`${args.scheduled_date}T00:00:00Z`).getUTCDay()
          ];
          const matches = availability.some((slot) => {
            if (slot.availability_type === 'specific') {
              return slot.date === args.scheduled_date;
            }
            return !!slot.days_of_week?.includes(weekday);
          });
          if (!matches) {
            const availDays = Array.from(new Set(
              availability
                .flatMap((s) => s.days_of_week ?? (s.date ? [s.date] : []))
                .filter(Boolean),
            )).join(', ');
            return jsonResult({
              success: false,
              error:
                `Employee is not available on ${args.scheduled_date} (${weekday}). ` +
                `Available days: ${availDays || 'none'}. ` +
                `Pick a scheduled_date matching one of the available days.`,
            });
          }
        }
      }

      // Resolve employee display info up-front so we can auto-fill notes
      // with the employee's role code when the caller didn't pass notes.
      // The frontend grid is keyed by notes.role, so without this the row
      // axis is wrong even if station_id is populated.
      const displayMap = await employeesService.findDisplayInfoByIds(
        ctx.organizationId,
        [args.employee_id],
      );
      const display = displayMap.get(args.employee_id);

      const department_id = args.department_id ?? ctx.departmentId;
      const station_id = args.station_id ?? ctx.stationId;
      const room_id = args.room_id ?? ctx.roomId;
      const bed_id = args.bed_id ?? ctx.bedId;
      const chair_id = args.chair_id ?? ctx.chairId;

      // The frontend grid is keyed by notes.role × date. LLM callers tend
      // to guess a role from the shift's eligible roles list, which lands
      // the row in the wrong column — so always override `role` with the
      // employee's real providerRole, preserving any other caller fields
      // (e.g. `rooms`). Also guard against `null` — zod allows only string
      // | undefined, but callers occasionally send literal null.
      let notes = args.notes;
      let notesObj: Record<string, unknown> | null = null;
      if (notes != null && notes.trim() !== '') {
        try {
          const parsed = JSON.parse(notes);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            notesObj = parsed as Record<string, unknown>;
          } else {
            notesObj = { text: notes };
          }
        } catch {
          notesObj = { text: notes };
        }
      }
      if (display?.role_code) {
        const merged: Record<string, unknown> = { ...(notesObj ?? {}) };
        merged.role = display.role_code;
        if (!Array.isArray(merged.rooms)) merged.rooms = [];
        notes = JSON.stringify(merged);
      } else if (notes == null) {
        notes = undefined;
      }

      const created = await employeeShiftService.create(
        ctx.organizationId,
        args.shift_id,
        {
          employee_id: args.employee_id,
          scheduled_date: args.scheduled_date,
          department_id,
          station_id,
          room_id,
          bed_id,
          chair_id,
          status: args.status,
          notes,
        },
        ctx.userId,
      );

      // Re-load with relations so the response carries the full shift +
      // employee context (used for the success card and LLM confirmation).
      const hydrated = await employeeShiftService.findOne(
        ctx.organizationId,
        created.id,
        ctx.userId,
      );

      const enrichedShift = hydrated.shift
        ? enrichShiftWithLocalTime(hydrated.shift, ctx.timezone)
        : hydrated.shift;

      return jsonResult({
        success: true,
        message: `Assigned ${display?.name ?? 'employee'} to ${hydrated.shift?.name ?? 'shift'}`,
        timezone: ctx.timezone,
        employee_shift: { ...hydrated, shift: enrichedShift },
        employee_name: display?.name ?? 'Unknown employee',
        employee_email: display?.email ?? null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return jsonResult({ success: false, error: message });
    }
  };

  return [
    {
      name: TOOL_NAMES.ASSIGN_EMPLOYEE_TO_SHIFT,
      description:
        "Assign an employee to an existing Shift template for a specific date (write operation). " +
        "Workflow: (1) call search_shifts to find the shift_id by name (e.g. 'NOC'), " +
        "(2) call get_employee_availability_schedule to confirm the employee is available, " +
        "(3) only then call this tool with scheduled_date set to the target YYYY-MM-DD date. " +
        "For recurring shifts (FULL_WEEK, WEEKDAYS, etc.), you MUST pass scheduled_date and call this tool ONCE PER DATE. " +
        "For ONE_TIME shifts, scheduled_date is optional (derived from the shift's start_at). " +
        "Returns { success: true, employee_shift } on success or { success: false, error } on conflict/validation failure.",
      inputSchema: assignSchema,
      handler: assignEmployeeToShift as (args: unknown) => SchedulingToolResult,
    },
  ];
}
