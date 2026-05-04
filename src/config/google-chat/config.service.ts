import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleChatConfigService {
  constructor(private configService: ConfigService) {}

  get verifySignature(): boolean {
    return this.configService.get<boolean>('googleChat.verifySignature', true);
  }

  get audience(): string {
    return this.configService.get<string>('googleChat.audience', '');
  }

  get issuer(): string {
    return this.configService.get<string>(
      'googleChat.issuer',
      'chat@system.gserviceaccount.com',
    );
  }

  get serviceAccountJson(): string {
    return this.configService.get<string>('googleChat.serviceAccountJson', '');
  }

  get appId(): string {
    return this.configService.get<string>('googleChat.appId', '');
  }

  get adminInstallUrl(): string {
    return this.configService.get<string>('googleChat.adminInstallUrl', '');
  }
}
