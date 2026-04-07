import { z } from 'zod';
import type { ProviderRolesService } from '../../../models/employees/services/provider-roles.service';
import { TOOL_NAMES } from '../../constants/mcp.constants';
import {
  jsonResult,
  SchedulingToolContext,
  SchedulingToolDescriptor,
  SchedulingToolResult,
} from './types';

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

export function buildRoleTools(
  providerRolesService: ProviderRolesService,
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
    const role = await providerRolesService.findOne(args.role_id);
    return jsonResult(role);
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
    const roles = await providerRolesService.findRolesForEmployee(
      args.employee_id,
      ctx.organizationId,
    );
    return jsonResult({ count: roles.length, roles });
  };

  const getShiftRoles = async (args: { shift_id: string }): SchedulingToolResult => {
    const roles = await providerRolesService.findRolesForShift(args.shift_id);
    return jsonResult({ count: roles.length, roles });
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
  ];
}
