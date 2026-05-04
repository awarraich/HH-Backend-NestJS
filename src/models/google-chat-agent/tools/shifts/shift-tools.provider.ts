import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { EmployeeShiftService } from '../../../organizations/scheduling/services/employee-shift.service';
import { ToolRegistry } from '../tool.registry';
import { buildListMyShiftsTool } from './list-my-shifts.tool';
import { buildGetShiftDetailsTool } from './get-shift-details.tool';
import { buildListAvailableShiftsTool } from './list-available-shifts.tool';

/**
 * Registers all shift-read tools (M5) with the agent's tool registry.
 *
 * The provider lives inside the agent module and depends on the
 * scheduling domain service (EmployeeShiftService) which exposes
 * self-only methods extended specifically for this caller pattern.
 */
@Injectable()
export class ShiftToolsProvider implements OnModuleInit {
  private readonly logger = new Logger(ShiftToolsProvider.name);

  constructor(
    private readonly registry: ToolRegistry,
    private readonly employeeShifts: EmployeeShiftService,
  ) {}

  onModuleInit(): void {
    this.registry.register(buildListMyShiftsTool(this.employeeShifts));
    this.registry.register(buildGetShiftDetailsTool(this.employeeShifts));
    this.registry.register(buildListAvailableShiftsTool(this.employeeShifts));
    this.logger.log('Registered M5 shift tools (3)');
  }
}
