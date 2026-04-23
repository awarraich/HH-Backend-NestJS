import { Injectable, Logger } from '@nestjs/common';
import { ZoomService } from './zoom.service';
import { GoogleMeetService } from './google-meet.service';

export type VideoPlatform = 'zoom' | 'google_meet' | 'teams';

export interface InterviewMeetingContext {
  platform: VideoPlatform;
  /** Interviewer (HR user) id — needed for Google Meet. */
  hrUserId: string;
  topic: string;
  description?: string;
  /** IANA timezone (e.g. "America/New_York") */
  timezone: string;
  /** Local YYYY-MM-DD. */
  date: string;
  /** Local HH:mm (24h). */
  time: string;
  durationMinutes: number;
  attendees?: string[];
}

export interface InterviewMeetingResult {
  /** The meeting join URL the candidate clicks. */
  joinUrl: string;
  /** Provider-specific meeting id (opaque). */
  meetingId?: string;
  /** Provider-side event id — persist so a future reschedule/cancel can update the real event. */
  providerEventId?: string;
  platform: VideoPlatform;
}

/**
 * Facade over the per-provider services. Every call that needs "get a
 * meeting link for this interview" goes through here so swap-in of new
 * providers (Teams, Whereby, etc.) happens in one place.
 */
@Injectable()
export class InterviewMeetingService {
  private readonly logger = new Logger(InterviewMeetingService.name);

  constructor(
    private readonly zoomService: ZoomService,
    private readonly googleMeetService: GoogleMeetService,
  ) {}

  async generateLink(
    ctx: InterviewMeetingContext,
  ): Promise<InterviewMeetingResult> {
    const startLocal = buildLocalIso(ctx.date, ctx.time);
    const endLocal = addMinutesToLocalIso(startLocal, ctx.durationMinutes);

    switch (ctx.platform) {
      case 'zoom': {
        if (!this.zoomService.isConfigured) {
          throw new Error(
            'Zoom is not configured on the server. Set ZOOM_ACCOUNT_ID, ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET.',
          );
        }
        const startUtcIso = localIsoToUtcIso(startLocal, ctx.timezone);
        const result = await this.zoomService.createMeeting({
          topic: ctx.topic,
          startUtcIso,
          durationMinutes: ctx.durationMinutes,
          timezone: ctx.timezone,
          agenda: ctx.description,
          attendees: ctx.attendees,
        });
        return {
          joinUrl: result.joinUrl,
          meetingId: result.meetingId,
          providerEventId: result.meetingId,
          platform: 'zoom',
        };
      }
      case 'google_meet': {
        if (!this.googleMeetService.isConfigured) {
          throw new Error(
            'Google OAuth is not configured on the server. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.',
          );
        }
        const result = await this.googleMeetService.createMeeting({
          hrUserId: ctx.hrUserId,
          summary: ctx.topic,
          description: ctx.description,
          startIsoLocal: startLocal,
          endIsoLocal: endLocal,
          timezone: ctx.timezone,
          attendees: ctx.attendees,
        });
        return {
          joinUrl: result.joinUrl,
          meetingId: result.eventId,
          providerEventId: result.eventId,
          platform: 'google_meet',
        };
      }
      case 'teams':
        throw new Error(
          'Microsoft Teams auto-link generation is not yet configured on this server.',
        );
      default: {
        const _exhaustive: never = ctx.platform;
        throw new Error(`Unknown platform: ${String(_exhaustive)}`);
      }
    }
  }
}

/** "2026-05-02" + "14:30" → "2026-05-02T14:30:00" (naive local ISO). */
function buildLocalIso(date: string, time: string): string {
  const cleanDate = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : '';
  const cleanTime = /^\d{2}:\d{2}(?::\d{2})?$/.test(time)
    ? time.length === 5
      ? `${time}:00`
      : time
    : '';
  if (!cleanDate || !cleanTime) {
    throw new Error(
      `Invalid interview date/time — expected YYYY-MM-DD and HH:mm, got "${date}" / "${time}".`,
    );
  }
  return `${cleanDate}T${cleanTime}`;
}

function addMinutesToLocalIso(localIso: string, minutes: number): string {
  const [datePart, timePart] = localIso.split('T');
  const [y, mo, d] = datePart.split('-').map(Number);
  const [h, mi, s] = timePart.split(':').map(Number);
  // Use UTC math so DST rules don't perturb the naive-local calculation —
  // the string we produce is purely a wall-clock value; tz is carried
  // separately in the payload.
  const base = Date.UTC(y, mo - 1, d, h, mi, s || 0);
  const shifted = new Date(base + minutes * 60_000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${shifted.getUTCFullYear()}-${pad(shifted.getUTCMonth() + 1)}-${pad(shifted.getUTCDate())}T${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}:${pad(shifted.getUTCSeconds())}`;
}

/**
 * Convert a naive wall-clock ISO string in a given IANA timezone to the
 * equivalent UTC instant. Uses Intl.DateTimeFormat to look up the
 * timezone's UTC offset at that date (handles DST correctly) without
 * pulling in a moment/luxon dependency.
 */
export function localIsoToUtcIso(localIso: string, timezone: string): string {
  const [datePart, timePart] = localIso.split('T');
  const [y, mo, d] = datePart.split('-').map(Number);
  const [h, mi, s] = timePart.split(':').map(Number);

  const asUtc = Date.UTC(y, mo - 1, d, h, mi, s || 0);
  const offsetMs = tzOffsetMs(timezone, new Date(asUtc));
  const utcMs = asUtc - offsetMs;
  return new Date(utcMs).toISOString();
}

/**
 * Returns the offset (in ms) that should be subtracted from a naive-UTC
 * timestamp to get the real UTC instant in the given IANA timezone.
 * i.e. for "America/New_York" during EDT, returns -4 * 60 * 60_000.
 */
function tzOffsetMs(timezone: string, at: Date): number {
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
  // Intl returns "24" for midnight in some locales — normalize.
  if (h === 24) h = 0;
  const asIfUtc = Date.UTC(y, mo - 1, d, h, mi, s);
  return asIfUtc - at.getTime();
}
