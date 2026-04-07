import type { ShiftService } from '../../../models/organizations/scheduling/services/shift.service';
import type { EmployeeShiftService } from '../../../models/organizations/scheduling/services/employee-shift.service';
import type { EmployeeAvailabilityService } from '../../../models/organizations/scheduling/services/employee-availability.service';
import type { ProviderRolesService } from '../../../models/employees/services/provider-roles.service';
import { buildShiftTools } from './shift-tools';
import { buildRoleTools } from './role-tools';
import { buildAvailabilityTools } from './availability-tools';
import { buildAssignmentTools } from './assignment-tools';
import { SchedulingToolContext, SchedulingToolDescriptor } from './types';

export function registerSchedulingHandlers(
  shiftService: ShiftService,
  employeeShiftService: EmployeeShiftService,
  availabilityService: EmployeeAvailabilityService,
  providerRolesService: ProviderRolesService,
  context: SchedulingToolContext,
): SchedulingToolDescriptor[] {
  return [
    ...buildShiftTools(shiftService, employeeShiftService, context),
    ...buildRoleTools(providerRolesService, context),
    ...buildAvailabilityTools(availabilityService, context),
    ...buildAssignmentTools(employeeShiftService, context),
  ];
}

export type { SchedulingToolContext, SchedulingToolDescriptor } from './types';
