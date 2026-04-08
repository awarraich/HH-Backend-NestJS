/**
 * Single source of truth for timezone handling in the scheduling agent.
 *
 * Timezones are supplied per-request by the client (the browser already knows
 * the user's IANA timezone via `Intl.DateTimeFormat().resolvedOptions().timeZone`),
 * not stored on any DB row. This keeps the agent always-correct: whatever the
 * user sees in their OS clock is what the agent uses.
 *
 * `resolveTimezone` is intentionally permissive — invalid or missing input
 * silently degrades to 'UTC' rather than throwing, so a misbehaving client
 * never breaks the chat endpoint.
 */

export const FALLBACK_TIMEZONE = 'UTC';

export function isValidIanaTimezone(tz: string): boolean {
  if (typeof tz !== 'string' || tz.trim().length === 0) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/**
 * Returns the supplied IANA timezone if valid, otherwise 'UTC'.
 * Use this at every boundary where a timezone enters the system from
 * untrusted input (request body, header, etc).
 */
export function resolveTimezone(input: string | null | undefined): string {
  if (!input) return FALLBACK_TIMEZONE;
  return isValidIanaTimezone(input) ? input : FALLBACK_TIMEZONE;
}
