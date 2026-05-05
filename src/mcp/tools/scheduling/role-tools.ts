import { z } from 'zod';
import type { ProviderRolesService } from '../../../models/employees/services/provider-roles.service';
import type { EmployeesService } from '../../../models/employees/services/employees.service';
import type { ShiftService } from '../../../models/organizations/scheduling/services/shift.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
} from './types';

/**
 * Normalize EmployeeShift.scheduled_date (typeorm `date` columns can come
 * back as Date or as string) to a plain YYYY-MM-DD string. Returns null
 * for missing/invalid input.
 */
function dateOnly(d: Date | string | null | undefined): string | null {
  if (!d) return null;
  if (typeof d === 'string') return d.slice(0, 10);
  if (d instanceof Date) {
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString().slice(0, 10);
  }
  return null;
}

/**
 * "Role" in this codebase = a row in the `provider_roles` catalog table
 * (e.g. RN, CNA, Sitter). Employees link to one provider_role via
 * `employees.provider_role_id`. These tools are thin views over
 * ProviderRolesService.
 *
 * Note: this differs from the original Django MCP design where "Role"
 * meant "a slot inside a shift" — that concept does not exist as a
 * standalone entity here.
 */

const listRolesSchema = {
  scoped_to_organization: z
    .boolean()
    .optional()
    .describe('When true, only return roles held by employees in this organization'),
};

const getRoleDetailsSchema = {
  role_id: z.string().uuid().describe('UUID of the provider_role'),
};

const searchRolesSchema = {
  query: z.string().min(1).describe('Free-text search across role code, name, and description'),
  limit: z.number().int().min(1).max(100).optional(),
};

const getEmployeeRolesSchema = {
  employee_id: z.string().uuid(),
};

const getShiftRolesSchema = {
  shift_id: z.string().uuid(),
};

const getShiftRoleCoverageSchema = {
  shift_id: z.string().uuid().describe('UUID of the shift'),
  scheduled_date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Expected YYYY-MM-DD')
    .optional()
    .describe(
      'When set, count only assignments with this exact scheduled_date. ' +
      'Omit to include every assignment on the shift across all dates.',
    ),
};

export function buildRoleTools(
  providerRolesService: ProviderRolesService,
  employeesService: EmployeesService,
  shiftService: ShiftService,
  ctx: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  const listRoles = async (args: {
    scoped_to_organization?: boolean;
  }): SchedulingToolResult => {
    const roles = args.scoped_to_organization
      ? await providerRolesService.listForOrganization(ctx.organizationId)
      : await providerRolesService.findAll();
    return jsonResult({ count: roles.length, roles });
  };

  const getRoleDetails = async (args: { role_id: string }): SchedulingToolResult => {
    try {
      const role = await providerRolesService.findOne(args.role_id);
      return jsonResult(role);
    } catch (err) {
      return jsonResult({
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const searchRoles = async (args: {
    query: string;
    limit?: number;
  }): SchedulingToolResult => {
    const roles = await providerRolesService.searchByText(args.query, args.limit);
    return jsonResult({ count: roles.length, roles });
  };

  const getEmployeeRoles = async (args: {
    employee_id: string;
  }): SchedulingToolResult => {
    // findRolesForEmployee throws when the employee doesn't exist in the
    // org. That's a routine miss for the LLM (asked about an unknown id) —
    // turn it into clean failure JSON instead of bubbling a 404 up to the
    // agent loop's catch-all.
    try {
      const [roles, displayMap] = await Promise.all([
        providerRolesService.findRolesForEmployee(args.employee_id, ctx.organizationId),
        employeesService.findDisplayInfoByIds(ctx.organizationId, [args.employee_id]),
      ]);
      const display = displayMap.get(args.employee_id);
      return jsonResult({
        count: roles.length,
        employee_name: display?.name ?? 'Unknown employee',
        employee_email: display?.email ?? null,
        roles,
      });
    } catch (err) {
      return jsonResult({
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const getShiftRoles = async (args: { shift_id: string }): SchedulingToolResult => {
    const roles = await providerRolesService.findRolesForShift(args.shift_id);
    return jsonResult({ count: roles.length, roles });
  };

  /**
   * "Which roles are eligible for this shift, and how many of each are
   * currently filled?" — pulls eligible roles from `shift_roles` and
   * compares against current assignments grouped by the assigned employee's
   * provider_role_id. There is no `required_count` column in shift_roles, so
   * we surface fill counts only; the caller is expected to phrase the answer
   * as "shift is eligible for X, currently 0 RNs assigned" rather than
   * inventing a required headcount that doesn't exist in the data.
   */
  const getShiftRoleCoverage = async (args: {
    shift_id: string;
    scheduled_date?: string;
  }): SchedulingToolResult => {
    const shift = await shiftService.findOne(
      ctx.organizationId,
      args.shift_id,
      ctx.userId,
    );

    const allAssignments = shift.employeeShifts ?? [];
    const assignments = args.scheduled_date
      ? allAssignments.filter(
          (es) => dateOnly(es.scheduled_date) === args.scheduled_date,
        )
      : allAssignments;

    // Count fills per provider_role_id.
    const filledByRole = new Map<string, number>();
    const unassignedRoleCount = { value: 0 };
    for (const a of assignments) {
      const roleId = a.employee?.provider_role_id;
      if (!roleId) {
        unassignedRoleCount.value += 1;
        continue;
      }
      filledByRole.set(roleId, (filledByRole.get(roleId) ?? 0) + 1);
    }

    const eligibleRoles = (shift.shiftRoles ?? [])
      .map((sr) => sr.providerRole)
      .filter((r): r is NonNullable<typeof r> => !!r);

    const eligibleRoleIds = new Set(eligibleRoles.map((r) => r.id));

    const coverage = eligibleRoles.map((r) => ({
      role_id: r.id,
      code: r.code,
      name: r.name,
      filled: filledByRole.get(r.id) ?? 0,
    }));

    // Roles that have assignments but are NOT in shift_roles — i.e. employees
    // assigned to this shift whose role isn't on the eligible list. The agent
    // should surface these as a configuration warning, not silently include
    // them in the "filled" totals.
    const unexpectedRoles: Array<{ role_id: string; filled: number }> = [];
    for (const [roleId, count] of filledByRole) {
      if (!eligibleRoleIds.has(roleId)) {
        unexpectedRoles.push({ role_id: roleId, filled: count });
      }
    }

    const empty = coverage.filter((c) => c.filled === 0);

    return jsonResult({
      shift_id: shift.id,
      shift_name: shift.name,
      scheduled_date: args.scheduled_date ?? null,
      total_assignments: assignments.length,
      total_eligible_roles: eligibleRoles.length,
      coverage,
      empty_eligible_roles: empty.map((c) => c.code ?? c.role_id),
      ...(unexpectedRoles.length > 0 ? { unexpected_roles: unexpectedRoles } : {}),
      ...(unassignedRoleCount.value > 0
        ? { assignments_without_role: unassignedRoleCount.value }
        : {}),
      note:
        'No required-count column exists on shift_roles. Coverage shows the eligible-role list and current fills only. ' +
        '`empty_eligible_roles` lists role codes that are eligible for this shift but have no one assigned (in the requested scope).',
    });
  };

  return [
    {
      name: TOOL_NAMES.LIST_ROLES,
      description:
        "List provider roles (e.g. RN, CNA, Sitter) from the catalog. Use when asked 'what roles do we have?' or 'list provider roles'. Pass scoped_to_organization=true to limit to roles actually held by employees in this org.",
      inputSchema: listRolesSchema,
      handler: listRoles as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_ROLE_DETAILS,
      description: 'Return full details for a single provider role.',
      inputSchema: getRoleDetailsSchema,
      handler: getRoleDetails as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.SEARCH_ROLES,
      description:
        'Free-text search across provider role code, name, and description. Use for autocomplete or to locate a role by partial name.',
      inputSchema: searchRolesSchema,
      handler: searchRoles as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_EMPLOYEE_ROLES,
      description:
        "Return the provider role(s) held by a specific employee. In this codebase an employee has at most one role.",
      inputSchema: getEmployeeRolesSchema,
      handler: getEmployeeRoles as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_SHIFT_ROLES,
      description:
        "Return the distinct provider roles represented in a shift's assignments, each annotated with how many employees on the shift hold that role.",
      inputSchema: getShiftRolesSchema,
      handler: getShiftRoles as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.GET_SHIFT_ROLE_COVERAGE,
      description:
        "Show eligible-roles vs. currently-filled coverage for a shift. " +
        "Pulls the shift's eligible roles from the shift_roles table and " +
        "compares against the assigned employees' provider_role to give you " +
        "per-role fill counts plus an `empty_eligible_roles` list of role " +
        "codes that have nobody assigned. Use this for 'what role slots does " +
        "this shift still need?', 'which roles on the AM shift are empty?', " +
        "'is anyone assigned as RN to this shift?'. " +
        "Pass scheduled_date to scope to one date; omit to count across all " +
        "dates this shift has assignments. " +
        "IMPORTANT: there is no required-count column in this codebase, so " +
        "the response shows current fills only — phrase replies as 'eligible " +
        "for X, currently Y filled', not 'needs N more'. " +
        "Different from get_shift_roles, which only lists roles ALREADY " +
        "represented in the assignments (and thus hides empty eligible roles).",
      inputSchema: getShiftRoleCoverageSchema,
      handler: getShiftRoleCoverage as (args: unknown) => SchedulingToolResult,
    },
  ];
}
