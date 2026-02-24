import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Wraps the SDK's Streamable HTTP transport for use with Node.js HTTP.
 * Stateless mode: no session tracking (sessionIdGenerator: undefined).
 */
export function createStreamableHttpTransport(): StreamableHTTPServerTransport {
  return new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
}

export type { IncomingMessage, ServerResponse };
