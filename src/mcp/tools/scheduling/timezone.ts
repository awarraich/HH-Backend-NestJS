/**
 * Single source of truth for timezone handling in the scheduling agent.
 *
 * Timezones are supplied per-request by the client (the browser already knows
 * the user's IANA timezone via `Intl.DateTimeFormat().resolvedOptions().timeZone`),
 * not stored on any DB row. This keeps the agent always-correct: whatever the
 * user sees in their OS clock is what the agent uses.
 *
 * `resolveTimezone` is intentionally permissive — invalid or missing input
 * silently degrades to the FALLBACK_TIMEZONE rather than throwing, so a
 * misbehaving client never breaks the chat endpoint.
 *
 * The fallback defaults to US Pacific (America/Los_Angeles) because this
 * platform's primary user base is in the Pacific timezone.
 */

export const FALLBACK_TIMEZONE = 'America/Los_Angeles';

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
 * Returns the supplied IANA timezone if valid, otherwise the FALLBACK_TIMEZONE
 * (America/Los_Angeles). Use this at every boundary where a timezone enters
 * the system from untrusted input (request body, header, etc).
 */
export function resolveTimezone(input: string | null | undefined): string {
  if (!input) return FALLBACK_TIMEZONE;
  return isValidIanaTimezone(input) ? input : FALLBACK_TIMEZONE;
}

/**
 * Convert a datetime string that represents a local time in the given
 * IANA timezone to its UTC equivalent.
 *
 * Example: localToUtc('2026-04-10T09:00:00', 'America/Los_Angeles')
 *   → Date representing 2026-04-10T16:00:00Z  (9 AM PDT = 4 PM UTC)
 *
 * If the timezone is 'UTC', returns `new Date(dateStr)` unchanged.
 * Invalid timezones fall back to America/Los_Angeles.
 */
export function localToUtc(dateStr: string, timezone: string): Date {
  const safeTz = resolveTimezone(timezone);
  const naive = new Date(dateStr);
  if (safeTz === 'UTC' || isNaN(naive.getTime())) return naive;

  // Parse the date/time components directly from the string so we are not
  // affected by the server's TZ environment variable.  `new Date(str)`
  // interprets timezone-naive strings in the server's local timezone,
  // which caused a double-offset bug when TZ != UTC.
  const match = dateStr.match(
    /(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2}))?)?/,
  );
  if (!match) return naive;

  const [, yr, mo, dy, hr = '0', mi = '0', sc = '0'] = match;
  const guess = Date.UTC(+yr, +mo - 1, +dy, +hr, +mi, +sc);

  // Format the guess (treated as UTC) in the target timezone to discover
  // what local time that UTC instant corresponds to.
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
  const parts = formatter.formatToParts(new Date(guess));
  const get = (type: Intl.DateTimeFormatPartTypes) =>
    parseInt(parts.find((p) => p.type === type)?.value ?? '0', 10);

  const localForGuess = Date.UTC(
    get('year'), get('month') - 1, get('day'),
    get('hour'), get('minute'), get('second'),
  );
  // offset = guess − localForGuess = how far ahead UTC is from local time
  const offsetMs = guess - localForGuess;
  return new Date(guess + offsetMs);
}
