/**
 * Renders shift timestamps in an organization's local timezone for
 * LLM-facing tool responses. Uses the built-in Intl.DateTimeFormat (no
 * external deps) which fully supports IANA zone names.
 *
 * The result intentionally exposes BOTH the raw UTC ISO strings (for
 * downstream tool chaining and machine consumption) AND human-readable
 * local-time fields (for the LLM to quote in user-facing replies).
 */

export interface LocalTimeView {
  /** Original UTC ISO 8601 string, untouched. */
  start_at_utc: string;
  end_at_utc: string;
  /** Local-time formatted strings, e.g. "Apr 7, 2026 11:00 PM". */
  local_start: string;
  local_end: string;
  /** Compact display, e.g. "Apr 7 11:00 PM – Apr 8 7:00 AM PKT". */
  local_time_display: string;
  /** The IANA timezone the local strings were rendered in. */
  timezone: string;
  /** Human-friendly tz abbreviation (e.g. "PKT", "EST"). */
  timezone_abbr: string;
}

const DATE_TIME_FORMATTER_CACHE = new Map<string, Intl.DateTimeFormat>();
const ABBR_FORMATTER_CACHE = new Map<string, Intl.DateTimeFormat>();

function getDateTimeFormatter(timezone: string): Intl.DateTimeFormat {
  let f = DATE_TIME_FORMATTER_CACHE.get(timezone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });
    DATE_TIME_FORMATTER_CACHE.set(timezone, f);
  }
  return f;
}

function getAbbreviationFormatter(timezone: string): Intl.DateTimeFormat {
  let f = ABBR_FORMATTER_CACHE.get(timezone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      timeZoneName: 'short',
    });
    ABBR_FORMATTER_CACHE.set(timezone, f);
  }
  return f;
}

function extractAbbreviation(date: Date, timezone: string): string {
  try {
    const parts = getAbbreviationFormatter(timezone).formatToParts(date);
    const part = parts.find((p) => p.type === 'timeZoneName');
    return part?.value ?? timezone;
  } catch {
    return timezone;
  }
}

/**
 * Renders a single shift's UTC timestamps into a `LocalTimeView`.
 * Falls back to UTC labels when the timezone is invalid.
 */
export function formatShiftLocalTimes(
  startAt: Date | string,
  endAt: Date | string,
  timezone: string,
): LocalTimeView {
  const start = startAt instanceof Date ? startAt : new Date(startAt);
  const end = endAt instanceof Date ? endAt : new Date(endAt);
  const safeTz = isValidTimezone(timezone) ? timezone : 'UTC';

  const fmt = getDateTimeFormatter(safeTz);
  const localStart = fmt.format(start);
  const localEnd = fmt.format(end);
  const abbr = extractAbbreviation(start, safeTz);

  return {
    start_at_utc: start.toISOString(),
    end_at_utc: end.toISOString(),
    local_start: localStart,
    local_end: localEnd,
    local_time_display: `${localStart} – ${localEnd} ${abbr}`,
    timezone: safeTz,
    timezone_abbr: abbr,
  };
}

/**
 * Decorates a shift-shaped record (anything with start_at and end_at) with
 * `local_time` view fields. Used by every shift-returning MCP tool so the
 * LLM never has to do timezone math itself.
 */
export function enrichShiftWithLocalTime<T extends { start_at: Date | string; end_at: Date | string }>(
  shift: T,
  timezone: string,
): T & { local_time: LocalTimeView } {
  return {
    ...shift,
    local_time: formatShiftLocalTimes(shift.start_at, shift.end_at, timezone),
  };
}

function isValidTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}
