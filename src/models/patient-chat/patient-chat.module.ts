import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PatientChatConversation } from './entities/patient-chat-conversation.entity';
import { PatientChatMessage } from './entities/patient-chat-message.entity';
import { User } from '../../authentication/entities/user.entity';
import { Patient } from '../patients/entities/patient.entity';
import { Organization } from '../organizations/entities/organization.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { PatientChatService } from './services/patient-chat.service';
import { PatientChatController } from './controllers/patient-chat.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      PatientChatConversation,
      PatientChatMessage,
      User,
      Patient,
      Organization,
    ]),
    AuthenticationModule,
  ],
  controllers: [PatientChatController],
  providers: [PatientChatService],
  exports: [TypeOrmModule, PatientChatService],
})
export class PatientChatModule {}
