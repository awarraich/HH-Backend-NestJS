import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { Employee } from './entities/employee.entity';
import { EmployeeProfile } from './entities/employee-profile.entity';
import { ProviderRole } from './entities/provider-role.entity';
import { EmployeeShift } from '../organizations/scheduling/entities/employee-shift.entity';
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
import { CalendarEvent } from './calendar/entities/calendar-event.entity';
import { AvailabilityRule } from './calendar/entities/availability-rule.entity';
import { TimeOffRequest } from './calendar/entities/time-off-request.entity';
import { WorkPreference } from './calendar/entities/work-preference.entity';
import { CalendarEventService } from './calendar/services/calendar-event.service';
import { AvailabilityRuleService } from './calendar/services/availability-rule.service';
import { TimeOffRequestService } from './calendar/services/time-off-request.service';
import { WorkPreferenceService } from './calendar/services/work-preference.service';
import { EmployeeCalendarController } from './calendar/controllers/employee-calendar.controller';
import { MyScheduleController } from './calendar/controllers/my-schedule.controller';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Employee,
      EmployeeProfile,
      ProviderRole,
      EmployeeShift,
      CalendarEvent,
      AvailabilityRule,
      TimeOffRequest,
      WorkPreference,
    ]),
    ConfigModule,
    AuthenticationModule,
    OrganizationsModule,
    AuditLogModule,
    EmailModule,
  ],
  controllers: [
    EmployeesController,
    ProviderRolesController,
    ExternalEmployeesController,
    EmployeeContextController,
    EmployeeCalendarController,
    MyScheduleController,
  ],
  providers: [
    EmployeesService,
    ProviderRolesService,
    OrganizationRoleGuard,
    EmployeeContextService,
    CalendarEventService,
    AvailabilityRuleService,
    TimeOffRequestService,
    WorkPreferenceService,
  ],
  exports: [TypeOrmModule, EmployeesService, ProviderRolesService],
})
export class EmployeesModule {}
