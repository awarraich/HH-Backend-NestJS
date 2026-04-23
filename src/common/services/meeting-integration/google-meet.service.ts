import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import axios, { AxiosError } from 'axios';
import { UserOAuthAccount } from '../../../authentication/entities/user-oauth-account.entity';

export interface GoogleMeetInput {
  hrUserId: string;
  summary: string;
  description?: string;
  /** ISO-8601 start; if an offset is supplied it's used, else tz below applies. */
  startIsoLocal: string;
  endIsoLocal: string;
  /** IANA timezone, e.g. "America/New_York". */
  timezone: string;
  attendees?: string[];
}

export interface GoogleMeetResult {
  joinUrl: string;
  eventId: string;
  htmlLink?: string;
}

/**
 * Google Meet link generator. Implemented via Google Calendar API v3 —
 * creating an event with `conferenceData.createRequest` is the only
 * supported way to mint a Meet room. The event is created on the HR
 * organizer's *primary* calendar, using the OAuth refresh token we
 * captured at sign-in.
 */
@Injectable()
export class GoogleMeetService {
  private readonly logger = new Logger(GoogleMeetService.name);

  constructor(
    @InjectRepository(UserOAuthAccount)
    private readonly oauthRepo: Repository<UserOAuthAccount>,
  ) {}

  get isConfigured(): boolean {
    return Boolean(
      process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET,
    );
  }

  /**
   * Ensure we have a non-expired access token for this HR user, refreshing
   * via the stored refresh_token if needed. Returns null when no account is
   * linked — callers should surface a "reconnect Google" prompt.
   */
  private async getAccessToken(userId: string): Promise<string | null> {
    const account = await this.oauthRepo.findOne({
      where: { user_id: userId, provider: 'google' },
    });
    if (!account || !account.refresh_token) return null;

    const now = Date.now();
    const expiresAt = account.access_token_expires_at?.getTime() ?? 0;
    if (account.access_token && expiresAt - 120_000 > now) {
      return account.access_token;
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error(
        'Google OAuth is not configured — set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.',
      );
    }

    try {
      const res = await axios.post<{
        access_token: string;
        expires_in: number;
        scope?: string;
        token_type: string;
      }>(
        'https://oauth2.googleapis.com/token',
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          refresh_token: account.refresh_token,
          grant_type: 'refresh_token',
        }).toString(),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          timeout: 15_000,
        },
      );

      account.access_token = res.data.access_token;
      account.access_token_expires_at = new Date(
        Date.now() + (res.data.expires_in ?? 3600) * 1000,
      );
      if (res.data.scope) account.scope = res.data.scope;
      await this.oauthRepo.save(account);
      return account.access_token;
    } catch (err) {
      const ax = err as AxiosError<{ error?: string; error_description?: string }>;
      const errorCode = ax.response?.data?.error;
      // `invalid_grant` = user revoked access or the refresh token was rotated out.
      // Clear the stored token so we don't keep retrying with a dead credential.
      if (errorCode === 'invalid_grant') {
        account.refresh_token = null;
        account.access_token = null;
        account.access_token_expires_at = null;
        await this.oauthRepo.save(account);
        return null;
      }
      this.logger.error(
        `Google token refresh failed: ${errorCode ?? ax.message}`,
      );
      throw err;
    }
  }

  async createMeeting(input: GoogleMeetInput): Promise<GoogleMeetResult> {
    const token = await this.getAccessToken(input.hrUserId);
    if (!token) {
      throw new Error(
        'Google account not connected. Ask the HR user to sign in with Google so we can create Meet links on their behalf.',
      );
    }

    const body = {
      summary: input.summary.slice(0, 1024),
      description: (input.description ?? '').slice(0, 8192),
      start: { dateTime: input.startIsoLocal, timeZone: input.timezone },
      end: { dateTime: input.endIsoLocal, timeZone: input.timezone },
      attendees: (input.attendees ?? []).map((email) => ({ email })),
      conferenceData: {
        createRequest: {
          requestId: `hh-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
          conferenceSolutionKey: { type: 'hangoutsMeet' },
        },
      },
      reminders: {
        useDefault: false,
        overrides: [
          { method: 'email', minutes: 60 },
          { method: 'popup', minutes: 10 },
        ],
      },
    };

    try {
      const res = await axios.post<{
        id: string;
        hangoutLink?: string;
        htmlLink?: string;
        conferenceData?: {
          entryPoints?: Array<{ entryPointType: string; uri: string }>;
        };
      }>(
        'https://www.googleapis.com/calendar/v3/calendars/primary/events',
        body,
        {
          params: { conferenceDataVersion: 1, sendUpdates: 'none' },
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          timeout: 20_000,
        },
      );

      const joinUrl =
        res.data.hangoutLink ||
        res.data.conferenceData?.entryPoints?.find(
          (e) => e.entryPointType === 'video',
        )?.uri;
      if (!joinUrl) {
        throw new Error(
          'Google created the event but no Meet link was returned. Try again in a moment.',
        );
      }
      return {
        joinUrl,
        eventId: res.data.id,
        htmlLink: res.data.htmlLink,
      };
    } catch (err) {
      const ax = err as AxiosError<{
        error?: { message?: string; status?: string };
      }>;
      const detail = ax.response?.data?.error?.message ?? ax.message;
      this.logger.error(
        `Google Calendar event creation failed: ${detail} (status ${ax.response?.status ?? 'unknown'})`,
      );
      throw new Error(`Google Meet link creation failed: ${detail}`);
    }
  }
}
