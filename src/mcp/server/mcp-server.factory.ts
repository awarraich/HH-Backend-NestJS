import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  MedicationsService,
  type MedicationAuditContext,
} from '../../models/patients/medications/medications.service';
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from '../constants/mcp.constants';
import { registerDigitalNurseHandlers } from '../tools/digital-nurse';

@Injectable()
export class McpServerFactory {
  constructor(private readonly medicationsService: MedicationsService) {}

  /**
   * Creates a new MCP server instance with digital-nurse tools bound to the given patient.
   * One server per request/session so tool handlers have the correct patient context.
   */
  create(patientId: string, auditContext?: MedicationAuditContext): McpServer {
    const server = new McpServer(
      {
        name: MCP_SERVER_NAME,
        version: MCP_SERVER_VERSION,
      },
      {
        capabilities: { tools: {} },
      },
    );

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

    return server;
  }
}
