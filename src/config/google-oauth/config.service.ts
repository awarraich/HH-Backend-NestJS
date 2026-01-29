import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleOAuthConfigService {
  constructor(private configService: ConfigService) {}

  get clientId(): string {
    return this.configService.get<string>('googleOAuth.clientId', '');
  }

  get clientSecret(): string {
    return this.configService.get<string>('googleOAuth.clientSecret', '');
  }

  get callbackURL(): string {
    return this.configService.get<string>('googleOAuth.callbackURL', '');
  }

  get enabled(): boolean {
    return this.configService.get<boolean>('googleOAuth.enabled', false);
  }
}

