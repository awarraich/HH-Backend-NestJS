import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosError } from 'axios';

interface ZoomTokenCache {
  accessToken: string;
  /** Epoch millis at which this token should be considered expired. */
  expiresAt: number;
}

export interface ZoomMeetingInput {
  topic: string;
  /** ISO-8601 instant in UTC (e.g. 2026-04-23T14:30:00Z). */
  startUtcIso: string;
  durationMinutes: number;
  /** IANA timezone, e.g. "America/New_York". */
  timezone: string;
  agenda?: string;
  attendees?: string[];
}

export interface ZoomMeetingResult {
  joinUrl: string;
  meetingId: string;
  password?: string;
  startUrl?: string;
}

/**
 * Zoom Server-to-Server OAuth client. Creates a meeting on the master account
 * user (`/users/me/meetings`). The access token is cached in-memory to avoid
 * fetching a fresh one per request — Zoom's account-credentials tokens last
 * ~1 hour.
 */
@Injectable()
export class ZoomService {
  private readonly logger = new Logger(ZoomService.name);
  private tokenCache: ZoomTokenCache | null = null;

  get isConfigured(): boolean {
    return Boolean(
      process.env.ZOOM_ACCOUNT_ID &&
        process.env.ZOOM_CLIENT_ID &&
        process.env.ZOOM_CLIENT_SECRET,
    );
  }

  private async getAccessToken(): Promise<string> {
    const now = Date.now();
    if (this.tokenCache && this.tokenCache.expiresAt - 120_000 > now) {
      return this.tokenCache.accessToken;
    }

    const accountId = process.env.ZOOM_ACCOUNT_ID;
    const clientId = process.env.ZOOM_CLIENT_ID;
    const clientSecret = process.env.ZOOM_CLIENT_SECRET;
    if (!accountId || !clientId || !clientSecret) {
      throw new Error(
        'Zoom is not configured — set ZOOM_ACCOUNT_ID, ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET.',
      );
    }

    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
      'base64',
    );
    const res = await axios.post<{
      access_token: string;
      expires_in: number;
      token_type: string;
      scope?: string;
    }>(
      'https://zoom.us/oauth/token',
      null,
      {
        params: {
          grant_type: 'account_credentials',
          account_id: accountId,
        },
        headers: {
          Authorization: `Basic ${basicAuth}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 15_000,
      },
    );

    this.tokenCache = {
      accessToken: res.data.access_token,
      expiresAt: now + (res.data.expires_in ?? 3600) * 1000,
    };
    return this.tokenCache.accessToken;
  }

  async createMeeting(input: ZoomMeetingInput): Promise<ZoomMeetingResult> {
    const token = await this.getAccessToken();

    const body = {
      topic: input.topic.slice(0, 200),
      // type: 2 = scheduled meeting (one-off). See Zoom API reference.
      type: 2,
      start_time: input.startUtcIso,
      duration: Math.max(5, Math.min(1440, input.durationMinutes)),
      timezone: input.timezone,
      agenda: (input.agenda ?? '').slice(0, 2000),
      settings: {
        join_before_host: false,
        waiting_room: true,
        mute_upon_entry: true,
        approval_type: 0,
        auto_recording: 'none',
        meeting_authentication: false,
        // Pre-register the attendees so Zoom shows their names in-meeting.
        // Only emails are sent — the candidate still gets the link via our
        // own invitation email.
        registrants_email_notification: false,
      },
    };

    try {
      const res = await axios.post<{
        id: number;
        join_url: string;
        start_url?: string;
        password?: string;
      }>('https://api.zoom.us/v2/users/me/meetings', body, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        timeout: 20_000,
      });

      return {
        joinUrl: res.data.join_url,
        meetingId: String(res.data.id),
        password: res.data.password,
        startUrl: res.data.start_url,
      };
    } catch (err) {
      const ax = err as AxiosError<{ message?: string; code?: number }>;
      const detail = ax.response?.data?.message ?? ax.message;
      this.logger.error(
        `Zoom createMeeting failed: ${detail} (status ${ax.response?.status ?? 'unknown'})`,
      );
      throw new Error(`Zoom meeting creation failed: ${detail}`);
    }
  }
}
