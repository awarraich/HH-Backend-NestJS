import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { UserChatConnection } from '../entities/user-chat-connection.entity';
import {
  NotificationDispatchLog,
  NotificationChannel,
  DispatchStatus,
  ReminderKind,
} from '../entities/notification-dispatch-log.entity';
import { GoogleChatChannelService } from './channels/google-chat-channel.service';
import { EmailChannelService } from './channels/email-channel.service';

export interface DispatchInput {
  orgId: string;
  userId: string;
  documentId: string;
  documentType: string;
  documentName: string;
  expiryDate: Date;
  reminderKind: ReminderKind;
}

export interface DispatchResult {
  channel: NotificationChannel | null;
  status: DispatchStatus;
  reason?: string;
  error?: string;
}

interface RenderedContent {
  chat: { text: string };
  email: { subject: string; html: string };
}

@Injectable()
export class NotificationDispatcherService {
  private readonly logger = new Logger(NotificationDispatcherService.name);
  private readonly portalUrl = process.env.HOME_HEALTH_AI_URL || 'https://homehealth.ai';
  private readonly chatRetryAttempts = 2;

  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(UserChatConnection)
    private readonly connections: Repository<UserChatConnection>,
    @InjectRepository(NotificationDispatchLog)
    private readonly dispatchLogs: Repository<NotificationDispatchLog>,
    private readonly chatChannel: GoogleChatChannelService,
    private readonly emailChannel: EmailChannelService,
  ) {}

  async dispatch(input: DispatchInput): Promise<DispatchResult> {
    const user = await this.users.findOne({ where: { id: input.userId } });
    if (!user) {
      this.logger.warn(`Dispatch skipped: no user with id ${input.userId}`);
      return { channel: null, status: 'skipped', reason: 'user-not-found' };
    }

    const alreadySent = await this.dispatchLogs.findOne({
      where: {
        user_id: user.id,
        document_id: input.documentId,
        reminder_kind: input.reminderKind,
        status: 'sent',
      },
    });
    if (alreadySent) {
      this.logger.log(
        `Dispatch skipped (idempotent): user=${user.id} doc=${input.documentId} kind=${input.reminderKind} already sent via ${alreadySent.channel}`,
      );
      return { channel: alreadySent.channel, status: 'skipped', reason: 'already-sent' };
    }

    const connection = await this.connections.findOne({
      where: { user_id: user.id, provider: 'google_chat' },
    });

    const content = this.render(input, user.firstName);

    if (this.canUseChat(connection)) {
      const chatResult = await this.tryChatSend(connection!, content.chat.text);
      if (chatResult.ok) {
        await this.recordLog(input, 'google_chat', 'sent');
        return { channel: 'google_chat', status: 'sent' };
      }
      this.logger.warn(
        `Chat send failed for user ${user.id} after ${this.chatRetryAttempts} attempts; falling back to email. Last error: ${chatResult.error}`,
      );
      await this.recordLog(input, 'google_chat', 'failed', chatResult.error);
    }

    try {
      await this.emailChannel.send(user.email, content.email.subject, content.email.html);
      await this.recordLog(input, 'email', 'sent');
      return { channel: 'email', status: 'sent' };
    } catch (err) {
      const msg = (err as Error).message;
      this.logger.error(`Email send failed for user ${user.id}: ${msg}`);
      await this.recordLog(input, 'email', 'failed', msg);
      return { channel: 'email', status: 'failed', error: msg };
    }
  }

  private canUseChat(connection: UserChatConnection | null): boolean {
    return (
      !!connection &&
      connection.status === 'connected' &&
      connection.chat_eligible &&
      !!connection.dm_space_name
    );
  }

  private async tryChatSend(
    connection: UserChatConnection,
    text: string,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    let lastError = '';
    for (let attempt = 1; attempt <= this.chatRetryAttempts; attempt++) {
      try {
        await this.chatChannel.sendDirectMessage(connection.dm_space_name!, text);
        return { ok: true };
      } catch (err) {
        lastError = (err as Error).message;
        this.logger.warn(
          `Chat send attempt ${attempt}/${this.chatRetryAttempts} failed: ${lastError}`,
        );
      }
    }
    return { ok: false, error: lastError };
  }

  private render(input: DispatchInput, firstName: string): RenderedContent {
    const daysLeft = this.daysUntilExpiry(input.expiryDate);
    const portalLink = `${this.portalUrl}/employee/documents/${input.documentId}`;
    const expiryStr = input.expiryDate.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });

    const headline =
      input.reminderKind === 'expired'
        ? `${input.documentName} has expired`
        : `${input.documentName} expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`;

    const chatText = `📋 ${headline}

Document: ${input.documentName}
Expires: ${expiryStr}

Please upload the renewed document: ${portalLink}`;

    const emailHtml = `<p>Hi ${firstName},</p>
<p>${headline}.</p>
<p><strong>Document:</strong> ${input.documentName}<br>
<strong>Expires:</strong> ${expiryStr}</p>
<p><a href="${portalLink}">Upload the renewed document in HomeHealth</a></p>
<p>— HomeHealth Reminders</p>`;

    return {
      chat: { text: chatText },
      email: { subject: `[HomeHealth] ${headline}`, html: emailHtml },
    };
  }

  private daysUntilExpiry(expiryDate: Date): number {
    const ms = expiryDate.getTime() - Date.now();
    return Math.max(0, Math.ceil(ms / (24 * 60 * 60 * 1000)));
  }

  private async recordLog(
    input: DispatchInput,
    channel: NotificationChannel,
    status: DispatchStatus,
    error?: string,
  ): Promise<void> {
    const existing = await this.dispatchLogs.findOne({
      where: {
        user_id: input.userId,
        document_id: input.documentId,
        reminder_kind: input.reminderKind,
        channel,
      },
    });

    if (existing) {
      existing.status = status;
      existing.error = error ?? null;
      existing.sent_at = new Date();
      existing.org_id = input.orgId;
      await this.dispatchLogs.save(existing);
      return;
    }

    const fresh = this.dispatchLogs.create({
      org_id: input.orgId,
      user_id: input.userId,
      document_id: input.documentId,
      document_type: input.documentType,
      reminder_kind: input.reminderKind,
      channel,
      status,
      error: error ?? null,
    });
    await this.dispatchLogs.save(fresh);
  }
}
