import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { chat, chat_v1 } from '@googleapis/chat';
import { JWT } from 'google-auth-library';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { GoogleChatConfigService } from '../../../config/google-chat/config.service';

interface ServiceAccountKey {
  type?: string;
  client_email: string;
  private_key: string;
  project_id?: string;
}

@Injectable()
export class GoogleChatClientService implements OnModuleInit {
  private readonly logger = new Logger(GoogleChatClientService.name);
  private chatClient: chat_v1.Chat | null = null;
  private clientEmail: string | null = null;

  constructor(private readonly config: GoogleChatConfigService) {}

  async onModuleInit(): Promise<void> {
    const raw = this.config.serviceAccountJson?.trim();
    if (!raw) {
      this.logger.warn(
        'GOOGLE_CHAT_SERVICE_ACCOUNT_JSON not set — Chat API client disabled. Reminders will not deliver via Chat.',
      );
      return;
    }

    let key: ServiceAccountKey;
    try {
      const content = raw.startsWith('{')
        ? raw
        : fs.readFileSync(path.resolve(process.cwd(), raw), 'utf-8');
      key = JSON.parse(content) as ServiceAccountKey;
      if (!key.client_email || !key.private_key) {
        throw new Error('JSON missing client_email or private_key');
      }
    } catch (err) {
      this.logger.error(
        `Failed to load Google Chat service account: ${(err as Error).message}`,
      );
      return;
    }

    const auth = new JWT({
      email: key.client_email,
      key: key.private_key,
      scopes: [
        // Send messages, list spaces, basic bot interaction.
        'https://www.googleapis.com/auth/chat.bot',
        // Lets the bot delete its OWN membership (used by leaveSpace when an
        // employee disconnects). Scoped to the calling app only — the bot
        // can't remove other users from spaces with this.
        'https://www.googleapis.com/auth/chat.memberships.app',
      ],
    });

    this.chatClient = chat({ version: 'v1', auth });
    this.clientEmail = key.client_email;
    this.logger.log(`Google Chat API client initialized as ${key.client_email}`);

    await this.smokeTest();
  }

  getClient(): chat_v1.Chat {
    if (!this.chatClient) {
      throw new Error(
        'Google Chat client not initialized — check GOOGLE_CHAT_SERVICE_ACCOUNT_JSON',
      );
    }
    return this.chatClient;
  }

  isAvailable(): boolean {
    return this.chatClient !== null;
  }

  private async smokeTest(): Promise<void> {
    if (!this.chatClient) return;
    try {
      const result = await this.chatClient.spaces.list({ pageSize: 1 });
      const total = result.data.spaces?.length ?? 0;
      this.logger.log(
        `Chat API smoke-test OK — bot is reachable (${total} space${total === 1 ? '' : 's'} visible on first page)`,
      );
    } catch (err) {
      const msg = (err as Error).message;
      this.logger.warn(`Chat API smoke-test failed: ${msg}`);
    }
  }
}
