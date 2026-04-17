import type { FastifyRequest } from 'fastify';
import { UnauthorizedException } from '@nestjs/common';

/**
 * Pull the authenticated user id off a Fastify request decorated by
 * `JwtAuthGuard` or `OptionalJwtAuthGuard`. Historically different
 * controllers have reached for `req.user.userId` or `req.user.sub`
 * depending on the guard's shape; centralising the lookup prevents
 * divergence and gives us one place to tighten the token contract later.
 *
 * Pass `{ throwIfMissing: false }` when the route is mounted behind
 * `OptionalJwtAuthGuard` and an anonymous caller is legitimate — the
 * overloaded signature widens the return type to `string | null` in that
 * case so TypeScript forces you to handle the "no user" branch.
 */
export function extractUserId(req: FastifyRequest): string;
export function extractUserId(
  req: FastifyRequest,
  opts: { throwIfMissing: true },
): string;
export function extractUserId(
  req: FastifyRequest,
  opts: { throwIfMissing: false },
): string | null;
export function extractUserId(
  req: FastifyRequest,
  opts: { throwIfMissing?: boolean } = {},
): string | null {
  const user = (req as unknown as {
    user?: { userId?: string | number; sub?: string | number };
  }).user;
  const id = user?.userId ?? user?.sub ?? null;
  if (id == null || id === '') {
    if (opts.throwIfMissing === false) return null;
    throw new UnauthorizedException('User ID not found');
  }
  return String(id);
}
