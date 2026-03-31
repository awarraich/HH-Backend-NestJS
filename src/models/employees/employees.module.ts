import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { Employee } from './entities/employee.entity';
import { EmployeeProfile } from './entities/employee-profile.entity';
import { ProviderRole } from './entities/provider-role.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { OrganizationsModule } from '../organizations/organizations.module';
import { AuditLogModule } from '../../common/services/audit/audit-log.module';
import { EmailModule } from '../../common/services/email/email.module';
import { EmployeesService } from './services/employees.service';
import { EmployeesController } from './controllers/employees.controller';
import { ProviderRolesService } from './services/provider-roles.service';
import { ProviderRolesController } from './controllers/provider-roles.controller';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';
import { ExternalEmployeesController } from './controllers/external-employees.controller';
import { EmployeeContextController } from './employee-context/controllers/employee-context.controller';
import { EmployeeContextService } from './employee-context/services/employee-context.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Employee, EmployeeProfile, ProviderRole]),
    ConfigModule,
    AuthenticationModule,
    OrganizationsModule,
    AuditLogModule,
    EmailModule,
  ],
  controllers: [EmployeesController, ProviderRolesController, ExternalEmployeesController, EmployeeContextController],
  providers: [
    EmployeesService,
    ProviderRolesService,
    OrganizationRoleGuard,
    EmployeeContextService,
  ],
  exports: [TypeOrmModule, EmployeesService, ProviderRolesService],
})
export class EmployeesModule {}
