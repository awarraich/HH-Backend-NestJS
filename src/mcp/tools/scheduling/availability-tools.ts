import { z } from 'zod';
import type { EmployeeAvailabilityService } from '../../../models/organizations/scheduling/services/employee-availability.service';
import type { EmployeesService } from '../../../models/employees/services/employees.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
} from './types';
import { enrichRecordsWithEmployeeNames } from './enrich-employees';

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

export function buildAvailabilityTools(
  availabilityService: EmployeeAvailabilityService,
  employeesService: EmployeesService,
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
    const enriched = await enrichRecordsWithEmployeeNames(
      records,
      employeesService,
      ctx.organizationId,
    );
    return jsonResult({ count: enriched.length, availability: enriched });
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
    const enriched = await enrichRecordsWithEmployeeNames(
      records,
      employeesService,
      ctx.organizationId,
    );
    return jsonResult({ count: enriched.length, candidates: enriched });
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
    const enriched = await enrichRecordsWithEmployeeNames(
      records,
      employeesService,
      ctx.organizationId,
    );
    return jsonResult({ count: enriched.length, schedule: enriched });
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
        "All parameters are optional. Data comes from the availability_rules table.",
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
        "NEVER invent or guess employee_id values. If you don't have a real UUID, call get_employee_availability without employee_id instead.",
      inputSchema: scheduleSchema,
      handler: getEmployeeAvailabilitySchedule as (args: unknown) => SchedulingToolResult,
    },
  ];
}
