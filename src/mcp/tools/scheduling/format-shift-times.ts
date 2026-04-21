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
  /** Local-time formatted strings, e.g. "Apr 7, 2026 11:00 PM" or "2:00 PM" for recurring. */
  local_start: string;
  local_end: string;
  /** Compact display, e.g. "Apr 7 11:00 PM – Apr 8 7:00 AM PKT" or "2:00 PM – 10:00 PM PKT (Weekdays)". */
  local_time_display: string;
  /** The IANA timezone the local strings were rendered in. */
  timezone: string;
  /** Human-friendly tz abbreviation (e.g. "PKT", "EST"). */
  timezone_abbr: string;
}

const DATE_TIME_FORMATTER_CACHE = new Map<string, Intl.DateTimeFormat>();
const TIME_ONLY_FORMATTER_CACHE = new Map<string, Intl.DateTimeFormat>();
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

function getTimeOnlyFormatter(timezone: string): Intl.DateTimeFormat {
  let f = TIME_ONLY_FORMATTER_CACHE.get(timezone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });
    TIME_ONLY_FORMATTER_CACHE.set(timezone, f);
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

/** Check if a shift uses a placeholder base date (time-only template). */
function isTemplateDateShift(startAt: Date): boolean {
  return startAt.getUTCFullYear() < 2000;
}

const RECURRENCE_LABELS: Record<string, string> = {
  FULL_WEEK: 'Every day',
  WEEKDAYS: 'Weekdays',
  WEEKENDS: 'Weekends',
  CUSTOM: 'Custom days',
};

/**
 * Renders a single shift's UTC timestamps into a `LocalTimeView`.
 * For recurring shifts with template dates (1970-01-01), shows time-only format.
 * Falls back to UTC labels when the timezone is invalid.
 */
export function formatShiftLocalTimes(
  startAt: Date | string,
  endAt: Date | string,
  timezone: string,
  recurrenceType?: string | null,
): LocalTimeView {
  const start = startAt instanceof Date ? startAt : new Date(startAt);
  const end = endAt instanceof Date ? endAt : new Date(endAt);
  const safeTz = isValidTimezone(timezone) ? timezone : 'UTC';
  const abbr = extractAbbreviation(start, safeTz);

  const isTemplate = isTemplateDateShift(start);
  const rt = (recurrenceType ?? '').toUpperCase();
  const isRecurring = rt && rt !== 'ONE_TIME';

  if (isTemplate || isRecurring) {
    // Time-only format for recurring/template shifts.
    // Shift times are stored as-is (07:00Z = 7:00 AM local), NOT as real
    // UTC, so we format with 'UTC' to avoid a double timezone conversion.
    const timeFmt = getTimeOnlyFormatter('UTC');
    const localStart = timeFmt.format(start);
    const localEnd = timeFmt.format(end);
    const recLabel = RECURRENCE_LABELS[rt] ?? rt;
    const display = isRecurring
      ? `${localStart} – ${localEnd} ${abbr} (${recLabel})`
      : `${localStart} – ${localEnd} ${abbr}`;

    return {
      start_at_utc: start.toISOString(),
      end_at_utc: end.toISOString(),
      local_start: localStart,
      local_end: localEnd,
      local_time_display: display,
      timezone: safeTz,
      timezone_abbr: abbr,
    };
  }

  // Full date+time for one-time shifts with real dates
  const fmt = getDateTimeFormatter(safeTz);
  const localStart = fmt.format(start);
  const localEnd = fmt.format(end);

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
export function enrichShiftWithLocalTime<
  T extends { start_at: Date | string; end_at: Date | string; recurrence_type?: string | null },
>(shift: T, timezone: string): T & { local_time: LocalTimeView } {
  return {
    ...shift,
    local_time: formatShiftLocalTimes(
      shift.start_at,
      shift.end_at,
      timezone,
      shift.recurrence_type,
    ),
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
