import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { GoogleOAuthConfigService } from './config.service';
import configuration from './configuration';

@Module({
  imports: [NestConfigModule.forFeature(configuration)],
  providers: [GoogleOAuthConfigService],
  exports: [GoogleOAuthConfigService],
})
export class GoogleOAuthConfigModule {}

