import { Module } from '@nestjs/common';
import { RecaptchaService } from './recaptcha.service';
import { RecaptchaConfigModule } from '../../../config/recaptcha/config.module';

@Module({
  imports: [RecaptchaConfigModule],
  providers: [RecaptchaService],
  exports: [RecaptchaService],
})
export class RecaptchaModule {}

