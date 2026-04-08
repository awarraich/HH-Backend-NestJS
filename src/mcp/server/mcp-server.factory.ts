import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  MedicationsService,
  type MedicationAuditContext,
} from '../../models/patients/medications/medications.service';
import { EmployeeDocumentsService } from '../../models/organizations/hr-files-setup/services/employee-documents.service';
import { OrganizationDocumentsService } from '../../models/organizations/compliance-documents/services/organization-documents.service';
import { OrganizationDocumentsChatService } from '../../models/organizations/compliance-documents/services/organization-documents-chat.service';
import { ShiftService } from '../../models/organizations/scheduling/services/shift.service';
import { EmployeeShiftService } from '../../models/organizations/scheduling/services/employee-shift.service';
import { EmployeeAvailabilityService } from '../../models/organizations/scheduling/services/employee-availability.service';
import { ProviderRolesService } from '../../models/employees/services/provider-roles.service';
import { EmployeesService } from '../../models/employees/services/employees.service';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from '../constants/mcp.constants';
import { registerDigitalNurseHandlers } from '../tools/digital-nurse';
import { registerEmployeeDocumentHandlers } from '../tools/employee-documents';
import { registerComplianceDocumentHandlers } from '../tools/compliance-documents';
import { registerSchedulingHandlers, SchedulingToolDescriptor } from '../tools/scheduling';
import { resolveTimezone } from '../tools/scheduling/timezone';

export interface EmployeeContext {
  organizationId: string;
  employeeId: string;
  userId: string;
}

export interface ComplianceContext {
  organizationId: string;
  userId: string;
}

export interface SchedulingContext {
  organizationId: string;
  userId: string;
  /**
   * IANA timezone supplied by the client (browser sends
   * `Intl.DateTimeFormat().resolvedOptions().timeZone`). Optional — falls
   * back to 'UTC' if missing or invalid.
   */
  timezone?: string | null;
}

@Injectable()
export class McpServerFactory {
  constructor(
    private readonly medicationsService: MedicationsService,
    private readonly employeeDocumentsService: EmployeeDocumentsService,
    private readonly complianceDocumentsService: OrganizationDocumentsService,
    private readonly complianceDocumentsChatService: OrganizationDocumentsChatService,
    private readonly shiftService: ShiftService,
    private readonly employeeShiftService: EmployeeShiftService,
    private readonly employeeAvailabilityService: EmployeeAvailabilityService,
    private readonly providerRolesService: ProviderRolesService,
    private readonly employeesService: EmployeesService,
  ) {}

  create(
    patientId: string | undefined,
    auditContext?: MedicationAuditContext,
    employeeContext?: EmployeeContext,
    complianceContext?: ComplianceContext,
    schedulingContext?: SchedulingContext,
  ): McpServer {
    const server = new McpServer(
      {
        name: MCP_SERVER_NAME,
        version: MCP_SERVER_VERSION,
      },
      {
        capabilities: { tools: {} },
      },
    );

    if (employeeContext) {
      const tools = registerEmployeeDocumentHandlers(
        this.employeeDocumentsService,
        employeeContext.organizationId,
        employeeContext.employeeId,
        employeeContext.userId,
      );
      for (const tool of tools) {
        server.registerTool(
          tool.name,
          {
            description: tool.description,
            inputSchema: tool.inputSchema as Parameters<
              McpServer['registerTool']
            >[1]['inputSchema'],
          },
          async (args: Record<string, unknown>) => {
            try {
              return await tool.handler(args as never);
            } catch (err) {
              const message = err instanceof Error ? err.message : String(err);
              return {
                content: [{ type: 'text' as const, text: message }],
                isError: true,
              };
            }
          },
        );
      }
    } else if (complianceContext) {
      const tools = registerComplianceDocumentHandlers(
        this.complianceDocumentsService,
        this.complianceDocumentsChatService,
        complianceContext.organizationId,
      );
      for (const tool of tools) {
        server.registerTool(
          tool.name,
          {
            description: tool.description,
            inputSchema: tool.inputSchema as Parameters<
              McpServer['registerTool']
            >[1]['inputSchema'],
          },
          async (args: Record<string, unknown>) => {
            try {
              return await tool.handler(args as never);
            } catch (err) {
              const message = err instanceof Error ? err.message : String(err);
              return {
                content: [{ type: 'text' as const, text: message }],
                isError: true,
              };
            }
          },
        );
      }
    } else if (schedulingContext) {
      const tools = registerSchedulingHandlers(
        this.shiftService,
        this.employeeShiftService,
        this.employeeAvailabilityService,
        this.providerRolesService,
        this.employeesService,
        {
          organizationId: schedulingContext.organizationId,
          userId: schedulingContext.userId,
          timezone: resolveTimezone(schedulingContext.timezone),
        },
      );
      for (const tool of tools) {
        server.registerTool(
          tool.name,
          {
            description: tool.description,
            inputSchema: tool.inputSchema as Parameters<
              McpServer['registerTool']
            >[1]['inputSchema'],
          },
          async (args: Record<string, unknown>) => {
            try {
              return await tool.handler(args as never);
            } catch (err) {
              const message = err instanceof Error ? err.message : String(err);
              return {
                content: [{ type: 'text' as const, text: message }],
                isError: true,
              };
            }
          },
        );
      }
    } else if (patientId) {
      const tools = registerDigitalNurseHandlers(this.medicationsService, patientId, auditContext);
      for (const tool of tools) {
        server.registerTool(
          tool.name,
          {
            description: tool.description,
            inputSchema: tool.inputSchema as Parameters<
              McpServer['registerTool']
            >[1]['inputSchema'],
          },
          async (args: Record<string, unknown>) => {
            try {
              return await tool.handler(args as never);
            } catch (err) {
              const message = err instanceof Error ? err.message : String(err);
              return {
                content: [{ type: 'text' as const, text: message }],
                isError: true,
              };
            }
          },
        );
      }
    }

    return server;
  }

  /**
   * Returns the raw scheduling tool descriptors without wrapping them in an
   * MCP server. Used by the LLM orchestrator to call tools in-process.
   */
  buildSchedulingTools(ctx: SchedulingContext): SchedulingToolDescriptor[] {
    return registerSchedulingHandlers(
      this.shiftService,
      this.employeeShiftService,
      this.employeeAvailabilityService,
      this.providerRolesService,
      this.employeesService,
      {
        organizationId: ctx.organizationId,
        userId: ctx.userId,
        timezone: resolveTimezone(ctx.timezone),
      },
    );
  }
}
