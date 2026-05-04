import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ReminderDispatchProducer, REMINDER_DISPATCH_QUEUE } from '../../jobs/producers/reminder-dispatch/reminder-dispatch.producer';
import { ReminderDispatchConsumer } from '../../jobs/consumers/reminder-dispatch/reminder-dispatch.consumer';
import { GoogleChatEventsController } from './controllers/google-chat-events.controller';
import { NotificationsDevController } from './controllers/notifications-dev.controller';
import { GoogleChatRequestGuard } from './guards/google-chat-request.guard';
import { IntegrationAdminGuard } from './guards/integration-admin.guard';
import { Organization } from '../organizations/entities/organization.entity';
import { Employee } from '../employees/entities/employee.entity';
import { BotEventHandlerService } from './services/bot-event-handler.service';
import { GoogleChatClientService } from './services/google-chat-client.service';
import { GoogleChatChannelService } from './services/channels/google-chat-channel.service';
import { EmailChannelService } from './services/channels/email-channel.service';
import { NotificationDispatcherService } from './services/notification-dispatcher.service';
import { DocumentExpiryScannerService } from './services/document-expiry-scanner.service';
import { OrganizationIntegrationService } from './services/organization-integration.service';
import { OrganizationIntegrationsController } from './controllers/organization-integrations.controller';
import { EmployeeNotificationsService } from './services/employee-notifications.service';
import { EmployeeNotificationsController } from './controllers/employee-notifications.controller';
import { InserviceCompletion } from '../organizations/hr-files-setup/entities/inservice-completion.entity';
import { OrganizationsModule } from '../organizations/organizations.module';
import { AuthenticationModule } from '../../authentication/auth.module';
import { GoogleChatConfigModule } from '../../config/google-chat/config.module';
import { EmailModule } from '../../common/services/email/email.module';
import { GoogleChatAgentModule } from '../google-chat-agent/google-chat-agent.module';
import { OrganizationIntegration } from './entities/organization-integration.entity';
import { UserChatConnection } from './entities/user-chat-connection.entity';
import { NotificationDispatchLog } from './entities/notification-dispatch-log.entity';
import { User } from '../../authentication/entities/user.entity';
import { OrganizationStaff } from '../organizations/staff-management/entities/organization-staff.entity';

@Module({
  imports: [
    GoogleChatConfigModule,
    EmailModule,
    AuthenticationModule,
    OrganizationsModule,
    GoogleChatAgentModule,
    BullModule.registerQueue({ name: REMINDER_DISPATCH_QUEUE }),
    TypeOrmModule.forFeature([
      OrganizationIntegration,
      UserChatConnection,
      NotificationDispatchLog,
      User,
      OrganizationStaff,
      Organization,
      Employee,
      InserviceCompletion,
    ]),
  ],
  controllers: [
    GoogleChatEventsController,
    NotificationsDevController,
    OrganizationIntegrationsController,
    EmployeeNotificationsController,
  ],
  providers: [
    GoogleChatRequestGuard,
    IntegrationAdminGuard,
    BotEventHandlerService,
    GoogleChatClientService,
    GoogleChatChannelService,
    EmailChannelService,
    NotificationDispatcherService,
    DocumentExpiryScannerService,
    OrganizationIntegrationService,
    EmployeeNotificationsService,
    ReminderDispatchProducer,
    ReminderDispatchConsumer,
  ],
  exports: [
    TypeOrmModule,
    GoogleChatClientService,
    GoogleChatChannelService,
    EmailChannelService,
    NotificationDispatcherService,
    DocumentExpiryScannerService,
    ReminderDispatchProducer,
  ],
})
export class NotificationsModule {}
