import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailConfigService {
  constructor(private configService: ConfigService) {}

  get host(): string {
    return this.configService.get<string>('email.host', 'smtp.gmail.com');
  }

  get port(): number {
    return this.configService.get<number>('email.port', 587);
  }

  get secure(): boolean {
    return this.configService.get<boolean>('email.secure', false);
  }

  get auth() {
    return {
      user: this.configService.get<string>('email.auth.user', ''),
      pass: this.configService.get<string>('email.auth.pass', ''),
    };
  }

  get from(): string {
    return this.configService.get<string>('email.from', 'noreply@example.com');
  }

  get fromName(): string {
    return this.configService.get<string>('email.fromName', 'Health Hub');
  }

  get verificationUrl(): string {
    return this.configService.get<string>('email.verificationUrl', '');
  }

  get passwordResetUrl(): string {
    return this.configService.get<string>('email.passwordResetUrl', '');
  }

  get mailersend() {
    return {
      apiKey: this.configService.get<string>('email.mailersend.apiKey', ''),
      fromEmail: this.configService.get<string>('email.mailersend.fromEmail', ''),
      fromName: this.configService.get<string>('email.mailersend.fromName', ''),
    };
  }

  get sendgrid() {
    return {
      apiKey: this.configService.get<string>('email.sendgrid.apiKey', ''),
    };
  }

  get supportEmail(): string {
    return this.configService.get<string>('email.supportEmail', 'support@homehealth.ai');
  }
}
