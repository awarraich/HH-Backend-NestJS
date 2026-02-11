import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Employee } from './entities/employee.entity';
import { EmployeeProfile } from './entities/employee-profile.entity';
import { AuthenticationModule } from '../../authentication/auth.module';
import { OrganizationsModule } from '../organizations/organizations.module';
import { AuditLogModule } from '../../common/services/audit/audit-log.module';
import { EmployeesService } from './services/employees.service';
import { EmployeesController } from './controllers/employees.controller';
import { OrganizationRoleGuard } from '../../common/guards/organization-role.guard';

@Module({
  imports: [
    TypeOrmModule.forFeature([Employee, EmployeeProfile]),
    AuthenticationModule,
    OrganizationsModule,
    AuditLogModule,
  ],
  controllers: [EmployeesController],
  providers: [EmployeesService, OrganizationRoleGuard],
  exports: [TypeOrmModule, EmployeesService],
})
export class EmployeesModule {}
