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
    // Use empty prefix: controllers already use full paths (e.g. v1/api/blogs). A non-empty prefix would double-prefix and cause 404 on /v1/api/blogs.
    return this.configService.get<string>('app.api.prefix', '') || '';
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
