import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { GoogleChatAgentConfigService } from './config.service';
import configuration from './configuration';

@Module({
  imports: [NestConfigModule.forFeature(configuration)],
  providers: [GoogleChatAgentConfigService],
  exports: [GoogleChatAgentConfigService],
})
export class GoogleChatAgentConfigModule {}
