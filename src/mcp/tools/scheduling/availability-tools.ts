import { z } from 'zod';
import type { EmployeeAvailabilityService } from '../../../models/organizations/scheduling/services/employee-availability.service';
import type { EmployeeShiftService } from '../../../models/organizations/scheduling/services/employee-shift.service';
import type { EmployeesService } from '../../../models/employees/services/employees.service';
import type { ShiftService } from '../../../models/organizations/scheduling/services/shift.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
  toBoundedInt,
} from './types';
import { enrichRecordsWithEmployeeNames } from './enrich-employees';
import { enrichRecordsWithAssignments } from './enrich-assignments';
import { enrichShiftWithLocalTime } from './format-shift-times';
import { FALLBACK_TIMEZONE } from './timezone';

/**
 * Compute the org-local YYYY-MM-DD for "today" so we can flag specific-date
 * availability slots that are already in the past. Without this, the model
 * happily summarises a 2026-04-24 slot as "the employee's availability"
 * weeks later, recommending an unscheduleable date.
 */
function todayInTimezone(timezone: string | undefined): string {
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

/**
 * Tag specific-date availability slots that fall before `todayIso` with
 * `is_past: true`. Recurring slots and undated slots are passed through
 * unchanged. Returns a new array — never mutates the input.
 */
function tagPastAvailability<T extends Record<string, unknown>>(
  records: T[],
  todayIso: string,
): Array<T & { is_past?: boolean }> {
  return records.map((r) => {
    const type = r['availability_type'];
    const date = r['date'];
    if (
      type === 'specific' &&
      typeof date === 'string' &&
      date.length >= 10 &&
      date < todayIso
    ) {
      return { ...r, is_past: true };
    }
    return r;
  });
}

const dateString = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Expected YYYY-MM-DD')
  .describe('YYYY-MM-DD');

const timeString = z
  .string()
  .regex(/^\d{2}:\d{2}$/, 'Expected HH:MM (24-hour)')
  .describe('HH:MM (24-hour)');

const getAvailabilitySchema = {
  employee_id: z.string().uuid().optional(),
  date: dateString.optional(),
  start_time: timeString.optional(),
  end_time: timeString.optional(),
  status: z.enum(['available', 'unavailable', 'tentative', 'booked']).optional(),
};

const searchAvailableSchema = {
  date: dateString,
  start_time: timeString,
  end_time: timeString,
  max_results: z.number().int().min(1).max(50).optional(),
};

const scheduleSchema = {
  employee_id: z.string().uuid(),
  start_date: dateString.optional(),
  end_date: dateString.optional(),
};

const listShiftsForEmployeeAvailabilitySchema = {
  employee_id: z
    .string()
    .uuid()
    .describe(
      'UUID of the employee whose availability we match against shifts. ' +
      'Resolve names to UUIDs via search_employees first — never invent.',
    ),
  status: z
    .string()
    .optional()
    .describe('Shift status filter; defaults to ACTIVE.'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe('Max shifts to return (default 25).'),
};

const SHIFT_DAYS_BY_RECURRENCE: Record<string, ReadonlyArray<string>> = {
  FULL_WEEK: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'],
  WEEKDAYS: ['MON', 'TUE', 'WED', 'THU', 'FRI'],
  WEEKENDS: ['SAT', 'SUN'],
};

const WEEKDAY_FROM_UTC = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];

/**
 * Determine which weekday codes a shift recurs on. For ONE_TIME shifts we
 * derive the day from start_at; for the named patterns we use the static
 * lookup; CUSTOM shifts read recurrence_days (stored as comma-separated
 * by typeorm's simple-array transformer).
 */
function shiftRecurrenceDays(shift: {
  recurrence_type?: string | null;
  recurrence_days?: string | string[] | null;
  start_at: Date | string;
}): string[] {
  const rt = (shift.recurrence_type ?? 'ONE_TIME').toUpperCase();
  if (SHIFT_DAYS_BY_RECURRENCE[rt]) {
    return [...SHIFT_DAYS_BY_RECURRENCE[rt]];
  }
  if (rt === 'CUSTOM') {
    const raw = shift.recurrence_days;
    if (Array.isArray(raw)) return raw.map((d) => String(d).toUpperCase());
    if (typeof raw === 'string')
      return raw.split(',').map((d) => d.trim().toUpperCase()).filter(Boolean);
    return [];
  }
  // ONE_TIME — use the start_at weekday
  const d = shift.start_at instanceof Date ? shift.start_at : new Date(shift.start_at);
  if (Number.isNaN(d.getTime())) return [];
  return [WEEKDAY_FROM_UTC[d.getUTCDay()]];
}

export function buildAvailabilityTools(
  availabilityService: EmployeeAvailabilityService,
  employeeShiftService: EmployeeShiftService,
  employeesService: EmployeesService,
  shiftService: ShiftService,
  ctx: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  const getEmployeeAvailability = async (args: {
    employee_id?: string | null;
    date?: string | null;
    start_time?: string | null;
    end_time?: string | null;
    status?: string | null;
  }): SchedulingToolResult => {
    const employeeId = args.employee_id ?? undefined;
    // When querying org-wide (no employee_id), ignore date/time filters
    // so we return ALL recurring availability rules, not just today's.
    const isOrgWide = !employeeId;
    const records = await availabilityService.findAvailability({
      employeeId,
      organizationId: ctx.organizationId,
      date: isOrgWide ? undefined : (args.date ?? undefined),
      startTime: isOrgWide ? undefined : (args.start_time ?? undefined),
      endTime: isOrgWide ? undefined : (args.end_time ?? undefined),
      status: args.status ?? undefined,
    });
    const withNames = await enrichRecordsWithEmployeeNames(
      records,
      employeesService,
      ctx.organizationId,
    );
    const enriched = await enrichRecordsWithAssignments(
      withNames,
      employeeShiftService,
      ctx.organizationId,
    );
    const tagged = tagPastAvailability(
      enriched as unknown as Array<Record<string, unknown>>,
      todayInTimezone(ctx.timezone),
    );
    return jsonResult({
      count: tagged.length,
      timezone: ctx.timezone,
      today: todayInTimezone(ctx.timezone),
      availability: tagged,
    });
  };

  const searchAvailableEmployees = async (args: {
    date: string;
    start_time: string;
    end_time: string;
    max_results?: number;
  }): SchedulingToolResult => {
    const records = await availabilityService.searchAvailableEmployees({
      date: args.date,
      startTime: args.start_time,
      endTime: args.end_time,
      organizationId: ctx.organizationId,
      maxResults: args.max_results,
    });
    const withNames = await enrichRecordsWithEmployeeNames(
      records,
      employeesService,
      ctx.organizationId,
    );
    const enriched = await enrichRecordsWithAssignments(
      withNames,
      employeeShiftService,
      ctx.organizationId,
    );
    const tagged = tagPastAvailability(
      enriched as unknown as Array<Record<string, unknown>>,
      todayInTimezone(ctx.timezone),
    );
    return jsonResult({
      count: tagged.length,
      timezone: ctx.timezone,
      today: todayInTimezone(ctx.timezone),
      candidates: tagged,
    });
  };

  const getEmployeeAvailabilitySchedule = async (args: {
    employee_id: string;
    start_date?: string;
    end_date?: string;
  }): SchedulingToolResult => {
    const records = await availabilityService.getEmployeeSchedule({
      employeeId: args.employee_id,
      startDate: args.start_date,
      endDate: args.end_date,
    });
    const withNames = await enrichRecordsWithEmployeeNames(
      records,
      employeesService,
      ctx.organizationId,
    );
    const enriched = await enrichRecordsWithAssignments(
      withNames,
      employeeShiftService,
      ctx.organizationId,
    );
    const tagged = tagPastAvailability(
      enriched as unknown as Array<Record<string, unknown>>,
      todayInTimezone(ctx.timezone),
    );
    return jsonResult({
      count: tagged.length,
      timezone: ctx.timezone,
      today: todayInTimezone(ctx.timezone),
      schedule: tagged,
    });
  };

  /**
   * Symmetric counterpart to search_available_employees: given an employee,
   * return the shifts whose local time window is fully covered by ≥1 of the
   * employee's recurring availability slots, on at least one day-of-week the
   * shift recurs on. We DO NOT enumerate per-date assignments here — that
   * is the agent's job after picking a shift. Overnight shifts (end before
   * start in 24h) are skipped to avoid silent misclassification; the agent
   * can fall back to SLOW PATH for those.
   */
  const listShiftsForEmployeeAvailability = async (args: {
    employee_id: string;
    status?: string;
    limit?: number;
  }): SchedulingToolResult => {
    const limit = toBoundedInt(args.limit, { fallback: 25, min: 1, max: 100 });

    // Pull all candidate shifts (status default ACTIVE). We keep the inner
    // page large so a small `limit` here still surveys the org's shifts.
    const { data: shifts } = await shiftService.findAll(
      ctx.organizationId,
      { page: 1, limit: 200, status: args.status ?? 'ACTIVE' },
      ctx.userId,
    );
    if (shifts.length === 0) {
      return jsonResult({ count: 0, shifts: [], note: 'No shifts in this organization.' });
    }

    // Pull the employee's availability slots, available status only.
    const availability = await availabilityService.findAvailability({
      employeeId: args.employee_id,
      organizationId: ctx.organizationId,
      status: 'available',
    });
    if (availability.length === 0) {
      return jsonResult({
        count: 0,
        shifts: [],
        note: 'Employee has no availability records.',
      });
    }

    const matches: Array<{
      id: string;
      name: string | null;
      recurrence_type: string | null;
      shift_type: string | null;
      local_time: ReturnType<typeof enrichShiftWithLocalTime>['local_time'];
      days_covered: string[];
      shift_recurrence_days: string[];
      is_overnight: boolean;
    }> = [];

    for (const shift of shifts) {
      const enriched = enrichShiftWithLocalTime(shift, ctx.timezone);
      const startHHMM = enriched.local_time?.local_start_24h;
      const endHHMM = enriched.local_time?.local_end_24h;
      if (!startHHMM || !endHHMM) continue;

      // Overnight: skip — string compare doesn't handle wraparound, and a
      // false positive here would mislead the model into a bad assignment.
      const isOvernight = endHHMM <= startHHMM;
      if (isOvernight) continue;

      const shiftDays = shiftRecurrenceDays(shift);
      if (shiftDays.length === 0) continue;

      const daysCovered: string[] = [];
      for (const day of shiftDays) {
        const covers = availability.some((slot) => {
          if (slot.availability_type !== 'recurring') return false;
          // Cast through ReadonlyArray<string> — slot.days_of_week is typed
          // as WeekdayCode[] but `day` is a generic string from the shift
          // recurrence helper. By construction the values match the WeekdayCode
          // domain (MON/TUE/…), so the cast is sound and avoids forcing the
          // helper's return type to leak that union upstream.
          const slotDays = slot.days_of_week as ReadonlyArray<string> | null | undefined;
          if (!slotDays?.includes(day)) return false;
          if (!slot.start_time || !slot.end_time) return false;
          // Time containment: slot fully wraps the shift window. Both sides
          // are HH:MM strings, so lexicographic compare is correct.
          return slot.start_time <= startHHMM && slot.end_time >= endHHMM;
        });
        if (covers) daysCovered.push(day);
      }

      if (daysCovered.length === 0) continue;

      matches.push({
        id: shift.id,
        name: shift.name,
        recurrence_type: shift.recurrence_type,
        shift_type: shift.shift_type,
        local_time: enriched.local_time,
        days_covered: daysCovered,
        shift_recurrence_days: shiftDays,
        is_overnight: false,
      });

      if (matches.length >= limit) break;
    }

    return jsonResult({
      count: matches.length,
      timezone: ctx.timezone,
      shifts: matches,
      note:
        'Each match shows the day-of-week codes the employee can cover. ' +
        'Overnight shifts are excluded — use SLOW PATH for those.',
    });
  };

  return [
    {
      name: TOOL_NAMES.GET_EMPLOYEE_AVAILABILITY,
      description:
        "Query the availability calendar from the database. " +
        "When called WITHOUT employee_id, returns availability for ALL employees in the organization — use this for 'what are the availabilities for my employees?' or 'show all availability'. " +
        "When called WITH employee_id, returns that specific employee's availability. " +
        "IMPORTANT: Do NOT pass a date parameter unless the user explicitly asks about a specific date. " +
        "When the user asks 'what are the availabilities?' without mentioning a date, omit the date parameter to get ALL recurring availability rules. " +
        "Passing today's date will filter to only rules matching today's day-of-week, which hides rules for other days. " +
        "All parameters are optional. Data comes from the availability_rules table. " +
        "Each record also includes `current_assignments`: a list of actual employee_shifts rows the employee is ALREADY assigned to (shift_id, shift_name, scheduled_date, status). " +
        "Use `current_assignments` — NOT the availability rule itself — to decide whether an employee is already booked on a shift. Availability means the employee CAN work that slot; an entry in `current_assignments` means they ARE already scheduled.",
      inputSchema: getAvailabilitySchema,
      handler: getEmployeeAvailability as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.SEARCH_AVAILABLE_EMPLOYEES,
      description:
        "'Who can cover this slot?' — given a date and time window, return employees in this organization who are available and have remaining capacity.",
      inputSchema: searchAvailableSchema,
      handler: searchAvailableEmployees as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_EMPLOYEE_AVAILABILITY_SCHEDULE,
      description:
        "Return ONE specific employee's availability calendar over a date range. " +
        "REQUIRES a valid employee_id UUID — resolve names to UUIDs via search_employees first. " +
        "NEVER invent or guess employee_id values. If you don't have a real UUID, call get_employee_availability without employee_id instead. " +
        "Each record also includes `current_assignments` listing the employee's actual shift bookings (shift_id, shift_name, scheduled_date, status). " +
        "Before reporting an employee as 'already assigned' to a shift, confirm the shift_id + scheduled_date exist in `current_assignments` — availability rules alone do NOT mean an assignment exists.",
      inputSchema: scheduleSchema,
      handler: getEmployeeAvailabilitySchedule as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.LIST_SHIFTS_FOR_EMPLOYEE_AVAILABILITY,
      description:
        "'Which shifts can this employee work?' — symmetric counterpart to " +
        "search_available_employees (which goes shift→employees). Given an " +
        "employee_id, returns the ACTIVE shifts whose local time window is fully " +
        "covered by at least one of the employee's recurring availability slots " +
        "on at least one day the shift recurs on. " +
        "Use this when the user asks 'what shifts is X available for?', " +
        "'which shifts can Alice cover?', or 'show me the shifts Bob qualifies for'. " +
        "REQUIRES a valid employee_id UUID — call search_employees first to resolve " +
        "names; never invent UUIDs. Each match includes `days_covered` (the " +
        "day-of-week codes the employee can actually cover for that shift) and " +
        "`shift_recurrence_days` (the days the shift itself runs). " +
        "Overnight shifts are intentionally skipped from this matcher to avoid " +
        "false positives; for those, use the SLOW PATH (search_shifts + " +
        "get_employee_availability_schedule + manual containment check).",
      inputSchema: listShiftsForEmployeeAvailabilitySchema,
      handler: listShiftsForEmployeeAvailability as (args: unknown) => SchedulingToolResult,
    },
  ];
}
