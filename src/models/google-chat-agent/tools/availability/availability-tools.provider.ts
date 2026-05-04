import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { AvailabilityRuleService } from '../../../employees/availability/services/availability-rule.service';
import { TimeOffRequestService } from '../../../employees/availability/services/time-off-request.service';
import { WorkPreferenceService } from '../../../employees/availability/services/work-preference.service';
import { ToolRegistry } from '../tool.registry';
import { buildGetMyAvailabilityTool } from './get-my-availability.tool';
import { buildGetMyTimeOffRequestsTool } from './get-my-time-off-requests.tool';
import { buildSetAvailabilityRuleTool } from './set-availability-rule.tool';
import { buildRequestTimeOffTool } from './request-time-off.tool';
import { buildCancelTimeOffRequestTool } from './cancel-time-off-request.tool';

/**
 * Registers M6 (read) + M7 (write) availability tools with the agent
 * registry. All tools are caller-self only — the underlying services
 * accept a userId and operate strictly on that user's data.
 */
@Injectable()
export class AvailabilityToolsProvider implements OnModuleInit {
  private readonly logger = new Logger(AvailabilityToolsProvider.name);

  constructor(
    private readonly registry: ToolRegistry,
    private readonly rules: AvailabilityRuleService,
    private readonly timeOff: TimeOffRequestService,
    private readonly prefs: WorkPreferenceService,
  ) {}

  onModuleInit(): void {
    this.registry.register(
      buildGetMyAvailabilityTool(this.rules, this.prefs),
    );
    this.registry.register(buildGetMyTimeOffRequestsTool(this.timeOff));
    this.registry.register(buildSetAvailabilityRuleTool(this.rules));
    this.registry.register(buildRequestTimeOffTool(this.timeOff));
    this.registry.register(buildCancelTimeOffRequestTool(this.timeOff));
    this.logger.log('Registered M6+M7 availability tools (5)');
  }
}
