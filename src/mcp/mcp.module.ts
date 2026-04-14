import { Module } from '@nestjs/common';
import { MedicationsModule } from '../models/patients/medications/medications.module';
import { OrganizationsModule } from '../models/organizations/organizations.module';
import { EmployeesModule } from '../models/employees/employees.module';
import { AuthenticationModule } from '../authentication/auth.module';
import { McpServerFactory } from './server/mcp-server.factory';
import { McpHttpHandlerService } from './mcp-http-handler.service';
import { OpenAiClient } from './orchestrator/openai.client';
import { SchedulingAgentService } from './orchestrator/scheduling-agent.service';
import { SchedulingAgentController } from './orchestrator/scheduling-agent.controller';

@Module({
  imports: [MedicationsModule, OrganizationsModule, EmployeesModule, AuthenticationModule],
  controllers: [SchedulingAgentController],
  providers: [
    McpServerFactory,
    McpHttpHandlerService,
    OpenAiClient,
    SchedulingAgentService,
  ],
  exports: [McpHttpHandlerService],
})
export class McpModule {}
