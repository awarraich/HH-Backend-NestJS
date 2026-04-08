import { z } from 'zod';
import type { EmployeesService } from '../../../models/employees/services/employees.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
} from './types';

/**
 * Employee directory tools used by the autonomous scheduling agent to resolve
 * names → ids. They wrap EmployeesService.findAll() and never expose internal
 * UUIDs in their tool descriptions, so the agent always queries by name first.
 */

const listEmployeesSchema = {
  status: z
    .string()
    .optional()
    .describe('Filter by employee status (default "active")'),
  limit: z.number().int().min(1).max(100).optional().describe('Max rows (default 50)'),
  page: z.number().int().min(1).optional().describe('Page number (default 1)'),
};

const searchEmployeesSchema = {
  query: z
    .string()
    .min(1)
    .describe('Free-text search across first name, last name, email, department, and position title'),
  limit: z.number().int().min(1).max(50).optional().describe('Max rows (default 25)'),
};

const listEmployeesByRoleSchema = {
  provider_role_id: z
    .string()
    .uuid()
    .describe('UUID of the provider_role. Resolve role names to ids via search_roles first.'),
  limit: z.number().int().min(1).max(100).optional(),
};

const listEmployeesByRoleNameSchema = {
  role_name: z
    .string()
    .min(1)
    .describe('Role name, code, or partial keyword (e.g. "RN", "Nurse", "OT", "Sitter")'),
  limit: z.number().int().min(1).max(100).optional(),
};

export function buildEmployeeTools(
  employeesService: EmployeesService,
  ctx: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  /**
   * Normalize a status filter so case mismatches between the LLM and the DB
   * don't cause silent empty results. The LLM tends to echo "ACTIVE" from
   * UI badges, while the actual DB column is lowercase 'active'.
   */
  const normalizeStatus = (s: string | undefined): string | undefined =>
    s ? s.trim().toLowerCase() : undefined;

  const listEmployees = async (args: {
    status?: string;
    limit?: number;
    page?: number;
  }): SchedulingToolResult => {
    // No default status filter — return everyone in the org so this tool
    // can never silently say "no employees" because of a case mismatch.
    const result = await employeesService.findAll(ctx.organizationId, {
      status: normalizeStatus(args.status),
      page: args.page ?? 1,
      limit: args.limit ?? 50,
    });
    return jsonResult({
      ...result,
      organization_id: ctx.organizationId,
      filter_applied: args.status ? `status=${normalizeStatus(args.status)}` : 'none',
    });
  };

  const searchEmployees = async (args: {
    query: string;
    limit?: number;
  }): SchedulingToolResult => {
    const result = await employeesService.findAll(ctx.organizationId, {
      search: args.query,
      page: 1,
      limit: args.limit ?? 25,
    });
    return jsonResult(result);
  };

  const listEmployeesByRole = async (args: {
    provider_role_id: string;
    limit?: number;
  }): SchedulingToolResult => {
    const result = await employeesService.findAll(ctx.organizationId, {
      provider_role_id: args.provider_role_id,
      page: 1,
      limit: args.limit ?? 50,
    });
    return jsonResult(result);
  };

  /**
   * Words/phrases that indicate the user is asking for ALL employees, not a
   * specific role. If the LLM accidentally passes one of these as role_name,
   * we hard-fail with an error that points it at list_employees instead.
   */
  const GENERIC_ROLE_INPUTS = new Set([
    'role',
    'roles',
    'all',
    'any',
    'all roles',
    'with role',
    'with roles',
    'employee',
    'employees',
    'all employees',
    'staff',
    'all staff',
    'everyone',
    'people',
    'team',
    'members',
  ]);

  /**
   * Compound tool: list active employees whose provider role matches the
   * given keyword. Uses a single SQL join (employees ⨝ provider_roles) so
   * the result is always consistent with the actual employee → role link
   * in the database — no two-step "lookup role id then filter employees"
   * chain that can drift if the resolver picks the wrong row.
   *
   * Hard-rejects generic inputs so the LLM cannot accidentally route a
   * "give me all employees" query through this tool. The error message
   * tells the model exactly which tool to call instead.
   */
  const listEmployeesByRoleName = async (args: {
    role_name: string;
    limit?: number;
  }): SchedulingToolResult => {
    const normalized = (args.role_name ?? '').trim().toLowerCase();
    if (!normalized || GENERIC_ROLE_INPUTS.has(normalized)) {
      return jsonResult({
        error: 'role_name_too_generic',
        provided_role_name: args.role_name,
        message:
          `"${args.role_name}" is not a specific role keyword. ` +
          'This tool requires a real role like "RN", "OT", "CNA", or "Sitter". ' +
          'For a directory of all employees with their roles attached, call ' +
          'list_employees instead — its response already includes provider_role ' +
          'on every row via a JOIN. Do not call this tool again with a generic word.',
        next_tool: 'list_employees',
      });
    }

    const employees = await employeesService.findByProviderRoleKeyword(
      ctx.organizationId,
      args.role_name,
      args.limit ?? 50,
    );

    // Distinct roles actually hit by the join — informational for the LLM
    // and for any frontend disambiguation card.
    const seen = new Map<string, { id: string; code: string; name: string }>();
    for (const e of employees) {
      const role = e.providerRole;
      if (role && !seen.has(role.id)) {
        seen.set(role.id, { id: role.id, code: role.code, name: role.name });
      }
    }

    if (employees.length === 0) {
      return jsonResult({
        count: 0,
        role_query: args.role_name,
        matched_roles: [],
        employees: [],
        message: `No active employees found for role keyword "${args.role_name}".`,
      });
    }

    return jsonResult({
      count: employees.length,
      role_query: args.role_name,
      matched_roles: Array.from(seen.values()),
      employees: employees.map((e) => ({
        id: e.id,
        user_id: e.user_id,
        status: e.status,
        provider_role_id: e.provider_role_id,
        provider_role: e.providerRole
          ? { id: e.providerRole.id, code: e.providerRole.code, name: e.providerRole.name }
          : null,
        user: e.user
          ? {
              id: e.user.id,
              email: e.user.email,
              firstName: e.user.firstName,
              lastName: e.user.lastName,
              full_name:
                `${e.user.firstName ?? ''} ${e.user.lastName ?? ''}`.trim() || e.user.email,
            }
          : null,
      })),
    });
  };

  return [
    {
      name: TOOL_NAMES.LIST_EMPLOYEES,
      description:
        "DEFAULT TOOL for any 'list / show / give me employees' query, including phrases like 'employees with roles', 'employees and their roles', 'all staff with roles', 'who works here'. Returns the full employee directory with each employee's provider_role JOINED IN — the role is in result.data[i].provider_role on every row, no second tool call needed. Use this whenever the user does NOT name a specific role keyword.",
      inputSchema: listEmployeesSchema,
      handler: listEmployees as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.SEARCH_EMPLOYEES,
      description:
        "Resolve an employee by name. Use this BEFORE asking the user for an employee id — search by first name, last name, email, department, or position. Returns multiple rows for ambiguous names so the caller can present a disambiguation list.",
      inputSchema: searchEmployeesSchema,
      handler: searchEmployees as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.LIST_EMPLOYEES_BY_ROLE,
      description:
        "List active employees holding a given provider role (e.g. all RNs, all CNAs). The caller must resolve a role name to provider_role_id via search_roles first.",
      inputSchema: listEmployeesByRoleSchema,
      handler: listEmployeesByRole as (args: unknown) => SchedulingToolResult,
    },
    {
      name: TOOL_NAMES.LIST_EMPLOYEES_BY_ROLE_NAME,
      description:
        "Filter employees by a SPECIFIC role keyword. Use ONLY when the user names a real role like 'RN', 'OT', 'CNA', 'Sitter', or 'Nurse'. Examples that fit: 'who are the RNs?', 'list OT employees', 'show me all CNAs'. " +
        "DO NOT use this tool when the user just says 'employees', 'with roles', 'all staff' — for those, use list_employees instead. " +
        "This tool will REJECT generic words ('role', 'roles', 'all', 'employees', 'staff') with an error pointing you at list_employees.",
      inputSchema: listEmployeesByRoleNameSchema,
      handler: listEmployeesByRoleName as (args: unknown) => SchedulingToolResult,
    },
  ];
}
