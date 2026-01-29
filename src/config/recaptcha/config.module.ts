import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { RecaptchaConfigService } from './config.service';
import configuration from './configuration';

@Module({
  imports: [NestConfigModule.forFeature(configuration)],
  providers: [RecaptchaConfigService],
  exports: [RecaptchaConfigService],
})
export class RecaptchaConfigModule {}

