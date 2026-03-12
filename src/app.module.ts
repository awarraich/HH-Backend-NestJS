import { Module } from '@nestjs/common';
import { AppConfigModule } from './config/app/config.module';
import { PostgresDatabaseProviderModule } from './providers/database/postgres/provider.module';
import { AuthenticationModule } from './authentication/auth.module';
import { AddressesModule } from './models/addresses/addresses.module';
import { OrganizationsModule } from './models/organizations/organizations.module';
import { PatientsModule } from './models/patients/patients.module';
import { ProvidersModule } from './models/providers/providers.module';
import { EmployeesModule } from './models/employees/employees.module';
import { AdminsModule } from './models/admins/admins.module';
import { CreditPackagesModule } from './models/credit-packages/credit-packages.module';
import { BlogModule } from './models/blog/blog.module';
import { PatientChatModule } from './models/patient-chat/patient-chat.module';
import { AiChatModule } from './models/ai-chat/ai-chat.module';
import { JobManagementModule } from './models/job-management/job-management.module';
import { AuditLogModule } from './common/services/audit/audit-log.module';
import { OnboardingStatusModule } from './common/services/onboarding-status/onboarding-status.module';
import { AppController } from './app.controller';
import { McpModule } from './mcp/mcp.module';

@Module({
  imports: [
    AppConfigModule,
    PostgresDatabaseProviderModule,
    AuthenticationModule,
    AddressesModule,
    OrganizationsModule,
    PatientsModule,
    ProvidersModule,
    EmployeesModule,
    AdminsModule,
    CreditPackagesModule,
    BlogModule,
    PatientChatModule,
    AiChatModule,
    JobManagementModule,
    AuditLogModule,
    OnboardingStatusModule,
    McpModule,
  ],
  controllers: [AppController],
  providers: [],
})
export class AppModule {}
