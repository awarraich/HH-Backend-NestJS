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
import { FALLBACK_TIMEZONE } from './timezone';

const WEEKDAY_FROM_UTC = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];

/**
 * Whether a shift recurs on `isoDate`. Honors recurrence_start_date /
 * recurrence_end_date bounds so a recurring shift that has been ended
 * doesn't show up as unfilled past its end.
 */
function shiftRunsOnDate(
  shift: {
    recurrence_type?: string | null;
    recurrence_days?: string | string[] | null;
    recurrence_start_date?: Date | string | null;
    recurrence_end_date?: Date | string | null;
    start_at: Date | string;
  },
  isoDate: string,
): boolean {
  const rt = (shift.recurrence_type ?? 'ONE_TIME').toUpperCase();
  if (rt === 'ONE_TIME') {
    const start = shift.start_at instanceof Date ? shift.start_at : new Date(shift.start_at);
    if (Number.isNaN(start.getTime())) return false;
    return start.toISOString().slice(0, 10) === isoDate;
  }
  // Recurrence bounds (inclusive).
  const dateOnly = (d: Date | string | null | undefined) =>
    d == null ? null : (d instanceof Date ? d.toISOString().slice(0, 10) : String(d).slice(0, 10));
  const recStart = dateOnly(shift.recurrence_start_date);
  const recEnd = dateOnly(shift.recurrence_end_date);
  if (recStart && isoDate < recStart) return false;
  if (recEnd && isoDate > recEnd) return false;

  const weekday = WEEKDAY_FROM_UTC[new Date(`${isoDate}T00:00:00Z`).getUTCDay()];
  if (rt === 'FULL_WEEK') return true;
  if (rt === 'WEEKDAYS') return ['MON', 'TUE', 'WED', 'THU', 'FRI'].includes(weekday);
  if (rt === 'WEEKENDS') return ['SAT', 'SUN'].includes(weekday);
  if (rt === 'CUSTOM') {
    const raw = shift.recurrence_days;
    const days = Array.isArray(raw)
      ? raw.map((d) => String(d).toUpperCase())
      : (typeof raw === 'string' ? raw.split(',') : [])
          .map((d) => d.trim().toUpperCase())
          .filter(Boolean);
    return days.includes(weekday);
  }
  return false;
}

function todayInTz(timezone: string): string {
  const tz = timezone && timezone.trim() ? timezone : FALLBACK_TIMEZONE;
  try {
    const fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    });
    const parts = fmt.formatToParts(new Date());
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
    return `${get('year')}-${get('month')}-${get('day')}`;
  } catch {
    return new Date().toISOString().slice(0, 10);
  }
}

function addDaysIso(iso: string, days: number): string {
  const d = new Date(`${iso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function* iterateDates(from: string, to: string): Generator<string> {
  if (from > to) return;
  let cursor = from;
  while (cursor <= to) {
    yield cursor;
    cursor = addDaysIso(cursor, 1);
  }
}

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

const listUnfilledShiftsSchema = {
  from_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Expected YYYY-MM-DD')
    .optional()
    .describe('Inclusive lower bound (defaults to today in the user timezone).'),
  to_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Expected YYYY-MM-DD')
    .optional()
    .describe('Inclusive upper bound (defaults to from_date + 7 days).'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe('Max shifts to return (default 25).'),
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
    // ShiftService.findOne throws NotFoundException for nonexistent or
    // org-foreign IDs. The agent loop's try/catch wraps that into a
    // success:false payload anyway, but turning it into a clean failure
    // here keeps tool-level callers (and direct tests) consistent — and
    // avoids the unwinding cost of an exception on a routine miss.
    try {
      const shift = await shiftService.findOne(
        ctx.organizationId,
        args.shift_id,
        ctx.userId,
      );
      return jsonResult(enrichShift(shift));
    } catch (err) {
      return jsonResult({
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
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

  /**
   * Find ACTIVE shifts that have at least one date in the requested window
   * with ZERO assigned employees. Reuses the leftJoinAndSelect on
   * employeeShifts inside ShiftService.findAll so we get assignments in
   * the date range without a second round-trip.
   *
   * Important: the data model has no `required_count` per shift or per role.
   * "Unfilled" here strictly means "no employees assigned on this date" — it
   * does NOT mean understaffed-relative-to-some-target. The agent should
   * phrase replies accordingly.
   */
  const listUnfilledShifts = async (args: {
    from_date?: string;
    to_date?: string;
    limit?: number;
  }): SchedulingToolResult => {
    const today = todayInTz(ctx.timezone);
    const from = args.from_date ?? today;
    const to = args.to_date ?? addDaysIso(from, 7);
    if (from > to) {
      return jsonResult({
        count: 0,
        shifts: [],
        error: `from_date (${from}) must be on or before to_date (${to}).`,
      });
    }
    const limit = toBoundedInt(args.limit, { fallback: 25, min: 1, max: 100 });

    // findAll's leftJoin on employeeShifts is filtered by the same date range,
    // so each returned shift carries only the assignments inside [from, to].
    const { data: shifts } = await shiftService.findAll(
      ctx.organizationId,
      { page: 1, limit: 200, status: 'ACTIVE', from_date: from, to_date: to },
      ctx.userId,
    );
    if (shifts.length === 0) {
      return jsonResult({
        count: 0,
        timezone: ctx.timezone,
        from_date: from,
        to_date: to,
        shifts: [],
        note: 'No ACTIVE shifts overlap this range.',
      });
    }

    // Group each shift's loaded assignments by scheduled_date.
    const unfilled: Array<{
      id: string;
      name: string | null;
      recurrence_type: string | null;
      shift_type: string | null;
      local_time: ReturnType<typeof enrichShift>['local_time'];
      unfilled_dates: string[];
      filled_dates_in_range: number;
    }> = [];

    for (const shift of shifts) {
      const enriched = enrichShift(shift);
      const assignmentsByDate = new Map<string, number>();
      for (const es of shift.employeeShifts ?? []) {
        // EmployeeShift.scheduled_date is typed as `string`, but TypeORM's
        // `date` columns can come back as a Date at runtime depending on the
        // driver/version. Widen first, then normalise to YYYY-MM-DD.
        const raw = es.scheduled_date as unknown;
        const date =
          raw instanceof Date
            ? raw.toISOString().slice(0, 10)
            : typeof raw === 'string'
              ? raw.slice(0, 10)
              : null;
        if (!date) continue;
        // Treat CANCELLED rows as not-filling — the slot is open again.
        if ((es.status ?? '').toUpperCase() === 'CANCELLED') continue;
        assignmentsByDate.set(date, (assignmentsByDate.get(date) ?? 0) + 1);
      }

      const unfilledDates: string[] = [];
      for (const date of iterateDates(from, to)) {
        if (!shiftRunsOnDate(shift, date)) continue;
        if ((assignmentsByDate.get(date) ?? 0) === 0) unfilledDates.push(date);
      }

      if (unfilledDates.length === 0) continue;

      unfilled.push({
        id: shift.id,
        name: shift.name,
        recurrence_type: shift.recurrence_type,
        shift_type: shift.shift_type,
        local_time: enriched.local_time,
        unfilled_dates: unfilledDates,
        filled_dates_in_range: assignmentsByDate.size,
      });

      if (unfilled.length >= limit) break;
    }

    return jsonResult({
      count: unfilled.length,
      timezone: ctx.timezone,
      from_date: from,
      to_date: to,
      shifts: unfilled,
      note:
        '"Unfilled" means zero non-cancelled assignments on that date. ' +
        'The data model has no required-count column, so this does not detect ' +
        'understaffing — only complete absences. Use get_shift_role_coverage to ' +
        'see per-role fills on a single shift.',
    });
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
    {
      name: TOOL_NAMES.LIST_UNFILLED_SHIFTS,
      description:
        "List ACTIVE shifts that have at least one date in the requested " +
        "window with ZERO non-cancelled assignments. Each result includes " +
        "the date list (`unfilled_dates`) within the window. " +
        "Use when asked 'what shifts are unfilled this week?', 'which shifts " +
        "have nobody on them?', 'where do I have gaps?'. " +
        "Defaults: from_date = today (in user TZ), to_date = from_date + 7 days. " +
        "IMPORTANT: 'unfilled' here strictly means 'zero employees assigned'. " +
        "There is no required-headcount column in the data, so this does NOT " +
        "detect understaffing relative to a target — use get_shift_role_coverage " +
        "to see per-role fill on a specific shift.",
      inputSchema: listUnfilledShiftsSchema,
      handler: listUnfilledShifts as (args: unknown) => SchedulingToolResult,
    },
  ];
}
