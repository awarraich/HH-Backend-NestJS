import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  MedicationsService,
  type MedicationAuditContext,
} from '../../models/patients/medications/medications.service';
import { EmployeeDocumentsService } from '../../models/organizations/hr-files-setup/services/employee-documents.service';
import { OrganizationDocumentsService } from '../../models/organizations/compliance-documents/services/organization-documents.service';
import { OrganizationDocumentsChatService } from '../../models/organizations/compliance-documents/services/organization-documents-chat.service';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from '../constants/mcp.constants';
import { registerDigitalNurseHandlers } from '../tools/digital-nurse';
import { registerEmployeeDocumentHandlers } from '../tools/employee-documents';
import { registerComplianceDocumentHandlers } from '../tools/compliance-documents';

export interface EmployeeContext {
  organizationId: string;
  employeeId: string;
  userId: string;
}

export interface ComplianceContext {
  organizationId: string;
  userId: string;
}

@Injectable()
export class McpServerFactory {
  constructor(
    private readonly medicationsService: MedicationsService,
    private readonly employeeDocumentsService: EmployeeDocumentsService,
    private readonly complianceDocumentsService: OrganizationDocumentsService,
    private readonly complianceDocumentsChatService: OrganizationDocumentsChatService,
  ) {}

  create(
    patientId: string | undefined,
    auditContext?: MedicationAuditContext,
    employeeContext?: EmployeeContext,
    complianceContext?: ComplianceContext,
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
}
