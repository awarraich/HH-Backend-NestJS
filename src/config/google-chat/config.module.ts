import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { GoogleChatConfigService } from './config.service';
import configuration from './configuration';

@Module({
  imports: [NestConfigModule.forFeature(configuration)],
  providers: [GoogleChatConfigService],
  exports: [GoogleChatConfigService],
})
export class GoogleChatConfigModule {}
