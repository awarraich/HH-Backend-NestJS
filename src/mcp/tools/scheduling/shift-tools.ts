import { z } from 'zod';
import type { ShiftService } from '../../../models/organizations/scheduling/services/shift.service';
import type { EmployeeShiftService } from '../../../models/organizations/scheduling/services/employee-shift.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
  toBoundedInt,
} from './types';
import { enrichShiftWithLocalTime } from './format-shift-times';

const listShiftsSchema = {
  shift_type: z
    .string()
    .optional()
    .describe(
      'Filter by shift type ("DAY", "NIGHT", "EVE"). ONLY pass this when the user ' +
      'explicitly asked for a specific type — many shifts store shift_type as NULL, ' +
      'and filtering will silently exclude them. If unsure, omit this field.',
    ),
  status: z.string().optional().describe('Filter by status (default ACTIVE)'),
  from_date: z.string().optional().describe('ISO date — only shifts starting on/after this date'),
  to_date: z.string().optional().describe('ISO date — only shifts ending on/before this date'),
  limit: z.number().int().min(1).max(100).optional().describe('Max rows (default 25)'),
};

const getShiftDetailsSchema = {
  shift_id: z.string().uuid().describe('UUID of the shift'),
};

const searchShiftsSchema = {
  query: z.string().min(1).describe('Free-text search against shift name and shift_type'),
  limit: z.number().int().min(1).max(100).optional(),
};

const getEmployeeShiftsSchema = {
  employee_id: z.string().uuid().describe('UUID of the employee'),
  status: z.string().optional(),
  from_date: z.string().optional(),
  to_date: z.string().optional(),
  limit: z.number().int().min(1).max(100).optional(),
};

type ListShiftsArgs = {
  shift_type?: string;
  status?: string;
  from_date?: string;
  to_date?: string;
  limit?: number;
};

export function buildShiftTools(
  shiftService: ShiftService,
  employeeShiftService: EmployeeShiftService,
  ctx: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  const enrichShift = <T extends { start_at: Date | string; end_at: Date | string }>(s: T) =>
    enrichShiftWithLocalTime(s, ctx.timezone);

  const listShifts = async (args: ListShiftsArgs): SchedulingToolResult => {
    const { data, total } = await shiftService.findAll(
      ctx.organizationId,
      {
        page: 1,
        limit: toBoundedInt(args.limit, { fallback: 50, min: 1, max: 100 }),
        shift_type: args.shift_type,
        status: args.status ?? 'ACTIVE',
        from_date: args.from_date,
        to_date: args.to_date,
      },
      ctx.userId,
    );
    // Enrich each shift with local time and annotate recurring shifts
    const enriched = data.map((s) => {
      const base = enrichShift(s);
      const rt = (s.recurrence_type ?? 'ONE_TIME').toUpperCase();
      if (rt !== 'ONE_TIME') {
        return {
          ...base,
          is_recurring: true,
          recurrence_type: rt,
          recurrence_note: `This is a recurring ${rt.replace(/_/g, ' ').toLowerCase()} shift template. The start/end times represent the daily time window, not a specific date.`,
        };
      }
      return { ...base, is_recurring: false };
    });
    return jsonResult({ total, timezone: ctx.timezone, shifts: enriched });
  };

  const getShiftDetails = async (args: { shift_id: string }): SchedulingToolResult => {
    const shift = await shiftService.findOne(ctx.organizationId, args.shift_id, ctx.userId);
    return jsonResult(enrichShift(shift));
  };

  const searchShifts = async (args: { query: string; limit?: number }): SchedulingToolResult => {
    const shifts = await shiftService.searchByText(
      ctx.organizationId,
      args.query,
      ctx.userId,
      toBoundedInt(args.limit, { fallback: 25, min: 1, max: 100 }),
    );
    return jsonResult({
      count: shifts.length,
      timezone: ctx.timezone,
      shifts: shifts.map(enrichShift),
    });
  };

  const getEmployeeShifts = async (args: {
    employee_id: string;
    status?: string;
    from_date?: string;
    to_date?: string;
    limit?: number;
  }): SchedulingToolResult => {
    const result = await employeeShiftService.findByEmployee(
      ctx.organizationId,
      args.employee_id,
      {
        page: 1,
        limit: toBoundedInt(args.limit, { fallback: 25, min: 1, max: 100 }),
        status: args.status,
        from_date: args.from_date,
        to_date: args.to_date,
      },
      ctx.userId,
    );
    // Each row carries a nested `shift`; enrich that nested object so the LLM
    // sees local times alongside the raw UTC timestamps.
    const enrichedRows = result.data.map((row) => ({
      ...row,
      shift: row.shift ? enrichShift(row.shift) : row.shift,
    }));
    return jsonResult({ ...result, timezone: ctx.timezone, data: enrichedRows });
  };

  return [
    {
      name: TOOL_NAMES.LIST_SHIFTS,
      description:
        "List shifts in this organization with optional filters. Use when asked 'what shifts are scheduled?', 'show morning shifts', or 'list this week's shifts'.",
      inputSchema: listShiftsSchema,
      handler: listShifts as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_SHIFT_DETAILS,
      description: 'Return full information for a single shift, including all assigned employees.',
      inputSchema: getShiftDetailsSchema,
      handler: getShiftDetails as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.SEARCH_SHIFTS,
      description:
        'Free-text search across shift name and shift_type. Use for autocomplete or to locate a shift by partial name.',
      inputSchema: searchShiftsSchema,
      handler: searchShifts as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_EMPLOYEE_SHIFTS,
      description:
        "List all shifts an employee is assigned to. Use when asked 'what shifts is X working?' or 'show employee X's schedule'.",
      inputSchema: getEmployeeShiftsSchema,
      handler: getEmployeeShifts as (args: unknown) => SchedulingToolResult,
    },
  ];
}
