import { localIsoToUtcIso } from './interview-meeting.service';

export interface IcsEventInput {
  /** Stable UID — reuse across reschedule so clients update the same event. */
  uid: string;
  summary: string;
  description: string;
  /** Naive local wall-clock ISO ("2026-05-02T14:30:00"). */
  startLocalIso: string;
  /** Naive local wall-clock ISO. */
  endLocalIso: string;
  /** IANA timezone, e.g. "America/New_York". */
  timezone: string;
  /** For video meetings — populates LOCATION + URL. For in-person, pass the address. */
  location?: string;
  organizer?: { name?: string; email: string };
  attendee?: { name?: string; email: string };
  /** Minutes before the event to fire a DISPLAY alarm. Default 30. */
  reminderMinutes?: number;
  /** RFC 5545 METHOD. REQUEST = initial invite; CANCEL = cancellation. */
  method?: 'REQUEST' | 'CANCEL';
  /** Sequence number — increment on reschedule so clients recognise the update. */
  sequence?: number;
}

/**
 * Build an RFC 5545 VCALENDAR body. Output is CRLF-line-terminated as the
 * spec requires — some mail clients (Outlook) silently reject LF-only .ics.
 *
 * Note on timezone handling: we intentionally emit DTSTART/DTEND with a
 * TZID property AND a VTIMEZONE block carrying the UTC offset at that
 * instant. For accuracy we pin a single STANDARD offset for the event
 * instant — we do not emit DST transition rules. For a 30-minute calendar
 * invite this is equivalent to what Google Calendar itself emits.
 */
export function buildIcs(input: IcsEventInput): string {
  const method = input.method ?? 'REQUEST';
  const sequence = input.sequence ?? 0;
  const reminder = Math.max(0, input.reminderMinutes ?? 30);

  const startUtc = icsDatetimeUtc(
    localIsoToUtcIso(input.startLocalIso, input.timezone),
  );
  const endUtc = icsDatetimeUtc(
    localIsoToUtcIso(input.endLocalIso, input.timezone),
  );
  const dtstamp = icsDatetimeUtc(new Date().toISOString());

  const offsetStr = formatUtcOffset(
    tzOffsetMinutesAt(input.timezone, new Date(input.startLocalIso)),
  );
  const vtimezone = [
    'BEGIN:VTIMEZONE',
    `TZID:${escapeText(input.timezone)}`,
    'BEGIN:STANDARD',
    `DTSTART:19700101T000000`,
    `TZOFFSETFROM:${offsetStr}`,
    `TZOFFSETTO:${offsetStr}`,
    `TZNAME:${escapeText(input.timezone)}`,
    'END:STANDARD',
    'END:VTIMEZONE',
  ].join('\r\n');

  const lines: string[] = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Home Health AI//Interview Invite//EN',
    'CALSCALE:GREGORIAN',
    `METHOD:${method}`,
    vtimezone,
    'BEGIN:VEVENT',
    `UID:${escapeText(input.uid)}`,
    `DTSTAMP:${dtstamp}`,
    `DTSTART:${startUtc}`,
    `DTEND:${endUtc}`,
    `SUMMARY:${escapeText(input.summary)}`,
    `DESCRIPTION:${escapeText(input.description)}`,
    `SEQUENCE:${sequence}`,
    `STATUS:${method === 'CANCEL' ? 'CANCELLED' : 'CONFIRMED'}`,
    `TRANSP:OPAQUE`,
  ];

  if (input.location) {
    lines.push(`LOCATION:${escapeText(input.location)}`);
    if (/^https?:\/\//i.test(input.location)) {
      lines.push(`URL:${escapeText(input.location)}`);
    }
  }
  if (input.organizer) {
    const cn = input.organizer.name
      ? `;CN=${escapeText(input.organizer.name)}`
      : '';
    lines.push(`ORGANIZER${cn}:MAILTO:${input.organizer.email}`);
  }
  if (input.attendee) {
    const cn = input.attendee.name
      ? `;CN=${escapeText(input.attendee.name)}`
      : '';
    lines.push(
      `ATTENDEE${cn};RSVP=TRUE;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT:MAILTO:${input.attendee.email}`,
    );
  }

  if (reminder > 0 && method !== 'CANCEL') {
    lines.push(
      'BEGIN:VALARM',
      'ACTION:DISPLAY',
      'DESCRIPTION:Interview reminder',
      `TRIGGER:-PT${reminder}M`,
      'END:VALARM',
    );
  }

  lines.push('END:VEVENT', 'END:VCALENDAR');
  // RFC 5545 §3.1: lines longer than 75 octets must be folded. Also use CRLF.
  return lines.map(foldLine).join('\r\n') + '\r\n';
}

function icsDatetimeUtc(iso: string): string {
  // "2026-05-02T14:30:00.000Z" → "20260502T143000Z"
  return iso.replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

function escapeText(s: string): string {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/,/g, '\\,')
    .replace(/;/g, '\\;');
}

function foldLine(line: string): string {
  if (line.length <= 75) return line;
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    const chunk = line.slice(i, i + 74);
    out.push(i === 0 ? chunk : ` ${chunk}`);
    i += 74;
  }
  return out.join('\r\n');
}

function tzOffsetMinutesAt(timezone: string, at: Date): number {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const parts = dtf.formatToParts(at);
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value);
  const y = get('year');
  const mo = get('month');
  const d = get('day');
  let h = get('hour');
  const mi = get('minute');
  const s = get('second');
  if (h === 24) h = 0;
  const asIfUtc = Date.UTC(y, mo - 1, d, h, mi, s);
  return Math.round((asIfUtc - at.getTime()) / 60_000);
}

function formatUtcOffset(minutes: number): string {
  const sign = minutes >= 0 ? '+' : '-';
  const abs = Math.abs(minutes);
  const h = String(Math.floor(abs / 60)).padStart(2, '0');
  const m = String(abs % 60).padStart(2, '0');
  return `${sign}${h}${m}`;
}

/**
 * Build a "Add to Google Calendar" deep link. The candidate clicks this and
 * lands on Google's pre-filled event-creation page.
 */
export function googleCalendarDeepLink(input: {
  summary: string;
  description: string;
  startLocalIso: string;
  endLocalIso: string;
  timezone: string;
  location?: string;
}): string {
  const fmt = (iso: string) =>
    icsDatetimeUtc(localIsoToUtcIso(iso, input.timezone));
  const params = new URLSearchParams({
    action: 'TEMPLATE',
    text: input.summary,
    dates: `${fmt(input.startLocalIso)}/${fmt(input.endLocalIso)}`,
    details: input.description,
    ctz: input.timezone,
  });
  if (input.location) params.set('location', input.location);
  return `https://calendar.google.com/calendar/render?${params.toString()}`;
}

/**
 * Build an "Add to Outlook.com Calendar" deep link (outlook.live.com /
 * outlook.office.com both accept the same query shape).
 */
export function outlookCalendarDeepLink(input: {
  summary: string;
  description: string;
  /** Must be full ISO with offset, e.g. "2026-05-02T14:30:00-04:00". */
  startUtcIso: string;
  endUtcIso: string;
  location?: string;
}): string {
  const params = new URLSearchParams({
    path: '/calendar/action/compose',
    rru: 'addevent',
    subject: input.summary,
    body: input.description,
    startdt: input.startUtcIso,
    enddt: input.endUtcIso,
  });
  if (input.location) params.set('location', input.location);
  return `https://outlook.live.com/calendar/0/deeplink/compose?${params.toString()}`;
}
