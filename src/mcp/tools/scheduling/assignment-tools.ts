import { z } from 'zod';
import type { EmployeeShiftService } from '../../../models/organizations/scheduling/services/employee-shift.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
} from './types';

const assignSchema = {
  shift_id: z
    .string()
    .uuid()
    .describe('UUID of the existing Shift template (look up via search_shifts first).'),
  employee_id: z.string().uuid().describe('UUID of the employee to assign.'),
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
  ctx: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  const assignEmployeeToShift = async (args: {
    shift_id: string;
    employee_id: string;
    department_id?: string;
    station_id?: string;
    room_id?: string;
    bed_id?: string;
    chair_id?: string;
    status?: string;
    notes?: string;
  }): SchedulingToolResult => {
    try {
      const result = await employeeShiftService.create(
        ctx.organizationId,
        args.shift_id,
        {
          employee_id: args.employee_id,
          department_id: args.department_id,
          station_id: args.station_id,
          room_id: args.room_id,
          bed_id: args.bed_id,
          chair_id: args.chair_id,
          status: args.status,
          notes: args.notes,
        },
        ctx.userId,
      );
      return jsonResult({ success: true, employee_shift: result });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return jsonResult({ success: false, error: message });
    }
  };

  return [
    {
      name: TOOL_NAMES.ASSIGN_EMPLOYEE_TO_SHIFT,
      description:
        "Assign an employee to an existing Shift template (write operation). " +
        "Workflow: (1) call search_shifts to find the shift_id by name (e.g. 'NOC'), " +
        "(2) call get_employee_availability_schedule to confirm the employee is available, " +
        "(3) only then call this tool. " +
        "Returns { success: true, employee_shift } on success or { success: false, error } on conflict/validation failure.",
      inputSchema: assignSchema,
      handler: assignEmployeeToShift as (args: unknown) => SchedulingToolResult,
    },
  ];
}
