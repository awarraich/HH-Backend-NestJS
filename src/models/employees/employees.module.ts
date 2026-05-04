import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { Employee } from './entities/employee.entity';
import { EmployeeProfile } from './entities/employee-profile.entity';
import { ProviderRole } from './entities/provider-role.entity';
import { User } from '../../authentication/entities/user.entity';
import { OrganizationStaff } from '../organizations/staff-management/entities/organization-staff.entity';
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
import { CalendarEvent } from './availability/entities/calendar-event.entity';
import { AvailabilityRule } from './availability/entities/availability-rule.entity';
import { TimeOffRequest } from './availability/entities/time-off-request.entity';
import { WorkPreference } from './availability/entities/work-preference.entity';
import { SchedulePreset } from './availability/entities/schedule-preset.entity';
import { CalendarEventService } from './availability/services/calendar-event.service';
import { AvailabilityRuleService } from './availability/services/availability-rule.service';
import { TimeOffRequestService } from './availability/services/time-off-request.service';
import { WorkPreferenceService } from './availability/services/work-preference.service';
import { SchedulePresetService } from './availability/services/schedule-preset.service';
import { EmployeeCalendarController } from './availability/controllers/employee-calendar.controller';
import { MyScheduleController } from './availability/controllers/my-schedule.controller';

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
      SchedulePreset,
      User,
      OrganizationStaff,
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
    SchedulePresetService,
  ],
  exports: [
    TypeOrmModule,
    EmployeesService,
    ProviderRolesService,
    AvailabilityRuleService,
    TimeOffRequestService,
    WorkPreferenceService,
  ],
})
export class EmployeesModule {}
