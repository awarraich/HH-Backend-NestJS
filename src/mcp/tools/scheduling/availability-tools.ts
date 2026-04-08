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
    employee_id?: string;
    date?: string;
    start_time?: string;
    end_time?: string;
    status?: string;
  }): SchedulingToolResult => {
    const records = availabilityService.findAvailability({
      employeeId: args.employee_id,
      organizationId: ctx.organizationId,
      date: args.date,
      startTime: args.start_time,
      endTime: args.end_time,
      status: args.status ?? 'available',
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
    const records = availabilityService.getEmployeeSchedule({
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
        "Query the availability calendar. Filter by employee, date, time window, or status. Recurring slots match regardless of date; time filters use containment (slot must fully cover the requested window).",
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
        "Return one employee's availability calendar over a date range. Recurring slots are returned as rules (not expanded into per-day rows).",
      inputSchema: scheduleSchema,
      handler: getEmployeeAvailabilitySchedule as (args: unknown) => SchedulingToolResult,
    },
  ];
}
