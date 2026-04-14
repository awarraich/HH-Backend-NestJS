import { Injectable, Logger } from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { JwtService } from '@nestjs/jwt';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { McpServerFactory } from './server/mcp-server.factory';
import { MCP_ERROR_MESSAGES } from './constants/mcp.constants';

const MCP_PATH = '/mcp';

export type McpCorsHeaders = Record<string, string>;

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve(undefined);
      }
    });
    req.on('error', reject);
  });
}

@Injectable()
export class McpHttpHandlerService {
  private readonly logger = new Logger(McpHttpHandlerService.name);

  constructor(
    private readonly mcpServerFactory: McpServerFactory,
    private readonly jwtService: JwtService,
  ) {}

  async handle(
    req: IncomingMessage,
    res: ServerResponse,
    corsHeaders: McpCorsHeaders,
  ): Promise<void> {
    for (const [key, value] of Object.entries(corsHeaders)) {
      res.setHeader(key, value);
    }
    const method = req.method ?? '';
    const url = req.url ?? '/';
    const path = url.split('?')[0];
    const jsonHeaders = { 'Content-Type': 'application/json', ...corsHeaders };

    if (path !== MCP_PATH) {
      res.writeHead(404, jsonHeaders);
      res.end(JSON.stringify({ error: 'Not Found' }));
      return;
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!token) {
      res.writeHead(401, jsonHeaders);
      res.end(JSON.stringify({ error: MCP_ERROR_MESSAGES.UNAUTHORIZED }));
      return;
    }

    let payload: { sub?: string };
    try {
      payload = this.jwtService.verify(token);
    } catch {
      res.writeHead(401, jsonHeaders);
      res.end(JSON.stringify({ error: MCP_ERROR_MESSAGES.UNAUTHORIZED }));
      return;
    }

    const userId = payload.sub;
    if (!userId) {
      res.writeHead(401, jsonHeaders);
      res.end(JSON.stringify({ error: MCP_ERROR_MESSAGES.UNAUTHORIZED }));
      return;
    }

    const ipAddress =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ??
      req.socket?.remoteAddress;
    const userAgent = (req.headers['user-agent'] as string) ?? undefined;
    const auditContext = {
      userId,
      ipAddress,
      userAgent,
    };

    let parsedBody: unknown;
    if (method === 'POST') {
      parsedBody = await readBody(req);
    }

    const body = parsedBody as {
      organizationId?: string;
      employeeId?: string;
      context?: string;
      timezone?: string;
    } | undefined;
    const organizationId = body?.organizationId;
    const employeeId = body?.employeeId;
    const contextType = body?.context;

    // Per-request timezone: prefer the request body, fall back to the
    // X-Timezone header. Both are client-supplied. The factory's
    // resolveTimezone() helper validates and falls back to UTC on bad input.
    const headerTimezone = req.headers['x-timezone'];
    const clientTimezone =
      body?.timezone ??
      (Array.isArray(headerTimezone) ? headerTimezone[0] : headerTimezone) ??
      null;

    const useEmployeeContext =
      typeof organizationId === 'string' &&
      typeof employeeId === 'string' &&
      organizationId.length > 0 &&
      employeeId.length > 0;

    const useComplianceContext =
      contextType === 'compliance' &&
      typeof organizationId === 'string' &&
      organizationId.length > 0 &&
      !useEmployeeContext;

    const useSchedulingContext =
      contextType === 'scheduling' &&
      typeof organizationId === 'string' &&
      organizationId.length > 0 &&
      !useEmployeeContext;

    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      let server;
      if (useEmployeeContext) {
        server = this.mcpServerFactory.create(undefined, undefined, {
          organizationId: organizationId!,
          employeeId: employeeId!,
          userId,
        });
      } else if (useComplianceContext) {
        server = this.mcpServerFactory.create(undefined, undefined, undefined, {
          organizationId: organizationId!,
          userId,
        });
      } else if (useSchedulingContext) {
        server = this.mcpServerFactory.create(
          undefined,
          undefined,
          undefined,
          undefined,
          {
            organizationId: organizationId!,
            userId,
            timezone: clientTimezone,
          },
        );
      } else {
        server = this.mcpServerFactory.create(userId, auditContext);
      }
      await server.connect(transport);

      await transport.handleRequest(req, res, parsedBody);
    } catch (err) {
      this.logger.error('MCP request handling failed', err);
      if (!res.headersSent) {
        res.writeHead(500, jsonHeaders);
        res.end(
          JSON.stringify({
            error: MCP_ERROR_MESSAGES.INTERNAL_ERROR,
          }),
        );
      }
    }
  }
}
