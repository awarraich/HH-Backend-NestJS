import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppConfigService {
  constructor(private configService: ConfigService) {}

  get port(): number {
    return this.configService.get<number>('app.port', 3000);
  }

  get environment(): string {
    return this.configService.get<string>('app.environment', 'development');
  }

  get apiPrefix(): string {
    return this.configService.get<string>('app.api.prefix', 'v1/api');
  }

  get frontendUrl(): string {
    return this.configService.get<string>('app.frontendUrl', '');
  }

  get isDevelopment(): boolean {
    return this.environment === 'development';
  }

  get isProduction(): boolean {
    return this.environment === 'production';
  }
}
