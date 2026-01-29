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
import { AuditLogModule } from './common/services/audit/audit-log.module';

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
    AuditLogModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
