import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../../authentication/entities/user.entity';
import { UserChatConnection } from '../entities/user-chat-connection.entity';
import { GoogleChatChannelService } from '../services/channels/google-chat-channel.service';
import { EmailChannelService } from '../services/channels/email-channel.service';
import {
  NotificationDispatcherService,
  DispatchInput,
  DispatchResult,
} from '../services/notification-dispatcher.service';
import {
  DocumentExpiryScannerService,
  ScanResult,
} from '../services/document-expiry-scanner.service';
import { ReminderKind } from '../entities/notification-dispatch-log.entity';

interface TestDmDto {
  email: string;
  text: string;
}

interface TestEmailDto {
  email: string;
  subject: string;
  html: string;
  text?: string;
}

interface TestDispatchDto {
  email: string;
  documentId: string;
  documentType: string;
  documentName: string;
  expiryDate: string;
  reminderKind: ReminderKind;
}

@Controller('dev/notifications')
export class NotificationsDevController {
  private readonly logger = new Logger(NotificationsDevController.name);

  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(UserChatConnection)
    private readonly connections: Repository<UserChatConnection>,
    private readonly chatChannel: GoogleChatChannelService,
    private readonly emailChannel: EmailChannelService,
    private readonly dispatcher: NotificationDispatcherService,
    private readonly scanner: DocumentExpiryScannerService,
  ) {}

  @Post('test-chat-dm')
  @HttpCode(HttpStatus.OK)
  async testChatDm(@Body() body: TestDmDto): Promise<{ sent: true; dm_space_name: string }> {
    this.assertDevOnly();
    if (!body?.email || !body?.text) {
      throw new BadRequestException('email and text are required');
    }

    const user = await this.users.findOne({ where: { email: body.email } });
    if (!user) {
      throw new BadRequestException(`No HomeHealth user with email ${body.email}`);
    }

    const connection = await this.connections.findOne({
      where: { user_id: user.id, provider: 'google_chat' },
    });
    if (!connection || !connection.dm_space_name) {
      throw new BadRequestException(
        `User ${body.email} has no Chat connection — add the bot in Chat first`,
      );
    }
    if (connection.status !== 'connected') {
      throw new BadRequestException(
        `Connection status is '${connection.status}' (need 'connected') — re-add the bot in Chat`,
      );
    }

    await this.chatChannel.sendDirectMessage(connection.dm_space_name, body.text);
    this.logger.log(`Test DM sent to ${body.email} via ${connection.dm_space_name}`);
    return { sent: true, dm_space_name: connection.dm_space_name };
  }

  @Post('test-email')
  @HttpCode(HttpStatus.OK)
  async testEmail(@Body() body: TestEmailDto): Promise<{ sent: true; to: string }> {
    this.assertDevOnly();
    if (!body?.email || !body?.subject || !body?.html) {
      throw new BadRequestException('email, subject, and html are required');
    }

    await this.emailChannel.send(body.email, body.subject, body.html, body.text);
    this.logger.log(`Test email sent to ${body.email}`);
    return { sent: true, to: body.email };
  }

  @Post('test-dispatch')
  @HttpCode(HttpStatus.OK)
  async testDispatch(
    @Body() body: TestDispatchDto,
  ): Promise<DispatchResult & { user_id: string; org_id: string }> {
    this.assertDevOnly();
    if (
      !body?.email ||
      !body?.documentId ||
      !body?.documentType ||
      !body?.documentName ||
      !body?.expiryDate ||
      !body?.reminderKind
    ) {
      throw new BadRequestException(
        'email, documentId, documentType, documentName, expiryDate, reminderKind required',
      );
    }

    const user = await this.users.findOne({ where: { email: body.email } });
    if (!user) {
      throw new BadRequestException(`No HomeHealth user with email ${body.email}`);
    }

    const connection = await this.connections.findOne({
      where: { user_id: user.id, provider: 'google_chat' },
    });
    const orgId = connection?.org_id;
    if (!orgId) {
      throw new BadRequestException(
        `User has no chat connection with org_id — seed one first or pass orgId explicitly`,
      );
    }

    const expiryDate = new Date(body.expiryDate);
    if (isNaN(expiryDate.getTime())) {
      throw new BadRequestException(`Invalid expiryDate: ${body.expiryDate}`);
    }

    const input: DispatchInput = {
      orgId,
      userId: user.id,
      documentId: body.documentId,
      documentType: body.documentType,
      documentName: body.documentName,
      expiryDate,
      reminderKind: body.reminderKind,
    };

    const result = await this.dispatcher.dispatch(input);
    this.logger.log(
      `Test dispatch: user=${user.id} doc=${body.documentId} kind=${body.reminderKind} → ${result.channel}/${result.status}`,
    );
    return { ...result, user_id: user.id, org_id: orgId };
  }

  @Post('run-scan')
  @HttpCode(HttpStatus.OK)
  async runScan(@Body() body: { referenceDate?: string }): Promise<ScanResult> {
    this.assertDevOnly();

    let referenceDate: Date | undefined;
    if (body?.referenceDate) {
      referenceDate = new Date(body.referenceDate);
      if (isNaN(referenceDate.getTime())) {
        throw new BadRequestException(`Invalid referenceDate: ${body.referenceDate}`);
      }
    }

    const result = await this.scanner.runScan(referenceDate);
    this.logger.log(
      `Manual scan: orgs=${result.orgsScanned} candidates=${result.candidatesFound} enqueued=${result.enqueued} malformed=${result.malformed}`,
    );
    return result;
  }

  private assertDevOnly(): void {
    if (process.env.NODE_ENV === 'production') {
      throw new NotFoundException();
    }
  }
}
