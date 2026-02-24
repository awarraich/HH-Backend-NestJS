import { Module } from '@nestjs/common';
import { MedicationsModule } from '../medications/medications.module';
import { DigitalNurseChatService } from './digital-nurse-chat.service';
import { DigitalNurseChatController } from './digital-nurse-chat.controller';

@Module({
  imports: [MedicationsModule],
  controllers: [DigitalNurseChatController],
  providers: [DigitalNurseChatService],
})
export class DigitalNurseModule {}
