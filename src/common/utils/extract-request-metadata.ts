import type { FastifyRequest } from 'fastify';

/**
 * E-signature audit metadata pulled off the request. Used by signature
 * endpoints to build a defensible audit trail per ESIGN / UETA guidance
 * (who signed, from where, with what user-agent).
 */
export interface RequestSignatureMetadata {
  ip: string | null;
  userAgent: string | null;
}

/**
 * Extract IP + User-Agent from a Fastify request. The IP prefers the
 * left-most entry of `X-Forwarded-For` (set by the load balancer / reverse
 * proxy) and falls back to Fastify's resolved `req.ip`. Both fields are
 * optional — callers should treat nulls as "unknown" rather than failing.
 */
export function extractRequestSignatureMetadata(
  req: FastifyRequest,
): RequestSignatureMetadata {
  const headers =
    (req as unknown as { headers?: Record<string, string | string[] | undefined> })
      .headers ?? {};
  const xff = headers['x-forwarded-for'];
  const xffIp =
    typeof xff === 'string'
      ? xff.split(',')[0]?.trim() || null
      : Array.isArray(xff) && typeof xff[0] === 'string'
        ? xff[0].split(',')[0]?.trim() || null
        : null;
  const directIp = (req as unknown as { ip?: string }).ip ?? null;
  const ip = xffIp ?? directIp ?? null;

  const uaHeader = headers['user-agent'];
  const userAgent =
    typeof uaHeader === 'string'
      ? uaHeader
      : Array.isArray(uaHeader) && typeof uaHeader[0] === 'string'
        ? uaHeader[0]
        : null;

  return { ip, userAgent };
}
