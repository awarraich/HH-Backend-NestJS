import { Injectable, Logger } from '@nestjs/common';
import { EmailService } from '../../../../common/services/email/email.service';

@Injectable()
export class EmailChannelService {
  private readonly logger = new Logger(EmailChannelService.name);

  constructor(private readonly emailService: EmailService) {}

  async send(toEmail: string, subject: string, html: string, text?: string): Promise<void> {
    await this.emailService.sendNotification(toEmail, subject, html, text);
    this.logger.log(`Sent notification email to ${toEmail}`);
  }
}
