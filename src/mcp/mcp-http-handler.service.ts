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
    req.on('data', (chunk) => chunks.push(chunk));
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
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : '';
    if (!token) {
      res.writeHead(401, jsonHeaders);
      res.end(
        JSON.stringify({ error: MCP_ERROR_MESSAGES.UNAUTHORIZED }),
      );
      return;
    }

    let payload: { sub?: string };
    try {
      payload = this.jwtService.verify(token) as { sub?: string };
    } catch {
      res.writeHead(401, jsonHeaders);
      res.end(
        JSON.stringify({ error: MCP_ERROR_MESSAGES.UNAUTHORIZED }),
      );
      return;
    }

    const patientId = payload.sub;
    if (!patientId) {
      res.writeHead(401, jsonHeaders);
      res.end(
        JSON.stringify({ error: MCP_ERROR_MESSAGES.UNAUTHORIZED }),
      );
      return;
    }

    const ipAddress =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ??
      req.socket?.remoteAddress;
    const userAgent = (req.headers['user-agent'] as string) ?? undefined;
    const auditContext = {
      userId: patientId,
      ipAddress,
      userAgent,
    };

    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      const server = this.mcpServerFactory.create(patientId, auditContext);
      await server.connect(transport);

      let parsedBody: unknown;
      if (method === 'POST') {
        parsedBody = await readBody(req);
      }

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
