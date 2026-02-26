import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  MedicationsService,
  type MedicationAuditContext,
} from '../../models/patients/medications/medications.service';
import { EmployeeDocumentsService } from '../../models/organizations/hr-files-setup/services/employee-documents.service';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from '../constants/mcp.constants';
import { registerDigitalNurseHandlers } from '../tools/digital-nurse';
import { registerEmployeeDocumentHandlers } from '../tools/employee-documents';

export interface EmployeeContext {
  organizationId: string;
  employeeId: string;
  userId: string;
}

@Injectable()
export class McpServerFactory {
  constructor(
    private readonly medicationsService: MedicationsService,
    private readonly employeeDocumentsService: EmployeeDocumentsService,
  ) {}

  /**
   * Creates a new MCP server instance. When employeeContext is provided, registers
   * employee-document tools only. Otherwise registers digital-nurse tools for the given patient.
   */
  create(
    patientId: string | undefined,
    auditContext?: MedicationAuditContext,
    employeeContext?: EmployeeContext,
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
            inputSchema: tool.inputSchema,
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
      const tools = registerDigitalNurseHandlers(
        this.medicationsService,
        patientId,
        auditContext,
      );
      for (const tool of tools) {
        server.registerTool(
          tool.name,
          {
            description: tool.description,
            inputSchema: tool.inputSchema,
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
}
