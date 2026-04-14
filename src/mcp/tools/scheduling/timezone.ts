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

/**
 * Convert a datetime string that represents a local time in the given
 * IANA timezone to its UTC equivalent.
 *
 * Example: localToUtc('2026-04-10T09:00:00', 'Asia/Karachi')
 *   → Date representing 2026-04-10T04:00:00Z  (9 AM PKT = 4 AM UTC)
 *
 * If the timezone is invalid or 'UTC', returns `new Date(dateStr)` unchanged.
 */
export function localToUtc(dateStr: string, timezone: string): Date {
  const safeTz = resolveTimezone(timezone);
  const naive = new Date(dateStr);
  if (safeTz === 'UTC' || isNaN(naive.getTime())) return naive;

  // Format the naive UTC instant in the target timezone to find the offset.
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: safeTz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
  const parts = formatter.formatToParts(naive);
  const get = (type: Intl.DateTimeFormatPartTypes) =>
    parseInt(parts.find((p) => p.type === type)?.value ?? '0', 10);

  const localForUtc = new Date(
    Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second')),
  );
  const offsetMs = localForUtc.getTime() - naive.getTime();
  return new Date(naive.getTime() - offsetMs);
}
