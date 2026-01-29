import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RecaptchaConfigService {
  constructor(private configService: ConfigService) {}

  get secretKey(): string {
    return this.configService.get<string>('recaptcha.secretKey', '6LfX9VgsAAAAAODeSHh0zb-bR5jHSMS9Afo_JOzg');
  }

  get siteKey(): string {
    return this.configService.get<string>('recaptcha.siteKey', '6LfX9VgsAAAAAHaT6SYYWboiYyjMJGrGJ_JrjQBV');
  }

  get enabled(): boolean {
    return this.configService.get<boolean>('recaptcha.enabled', false);
  }

  get verifyUrl(): string {
    return this.configService.get<string>(
      'recaptcha.verifyUrl',
      'https://www.google.com/recaptcha/api/siteverify',
    );
  }
}

