/**
 * Display helpers shared across card renderers.
 *
 * Time formatting deliberately stays UTC for now — when a real timezone
 * column lands on User/Organization (M2 caveat), thread it through here.
 */

const DAY_NAMES = [
  'Sunday',
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
];

/** "Mon Jun 03 · 8:00 AM – 4:00 PM UTC" */
export function formatShiftWindow(startIso: string, endIso: string): string {
  const start = new Date(startIso);
  const end = new Date(endIso);
  return `${DAY_NAMES[start.getUTCDay()].slice(0, 3)} ${monthName(start.getUTCMonth())} ${pad2(start.getUTCDate())} · ${formatTime(start)} – ${formatTime(end)} UTC`;
}

/** "8:00 AM" */
export function formatTime(d: Date): string {
  let h = d.getUTCHours();
  const m = d.getUTCMinutes();
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12 || 12;
  return `${h}:${pad2(m)} ${ampm}`;
}

/** "Jun 03" */
export function formatDateShort(yyyyMmDd: string): string {
  const [y, m, d] = yyyyMmDd.split('-').map(Number);
  return `${monthName((m ?? 1) - 1)} ${pad2(d ?? 1)}, ${y}`;
}

export function locationLabel(loc: {
  department: string | null;
  station: string | null;
  room: string | null;
  bed: string | null;
  chair: string | null;
}): string | null {
  const parts = [
    loc.department,
    loc.station,
    loc.room,
    loc.bed,
    loc.chair,
  ].filter((p): p is string => Boolean(p));
  return parts.length === 0 ? null : parts.join(' · ');
}

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}

function monthName(zeroBasedMonth: number): string {
  return [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ][zeroBasedMonth] ?? '???';
}
