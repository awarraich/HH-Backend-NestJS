import { Module } from '@nestjs/common';
import { MedicationsModule } from '../models/patients/medications/medications.module';
import { OrganizationsModule } from '../models/organizations/organizations.module';
import { EmployeesModule } from '../models/employees/employees.module';
import { AuthenticationModule } from '../authentication/auth.module';
import { McpServerFactory } from './server/mcp-server.factory';
import { McpHttpHandlerService } from './mcp-http-handler.service';
import { SchedulingAgentService } from './orchestrator/scheduling-agent.service';
import { SchedulingAgentController } from './orchestrator/scheduling-agent.controller';
import { LlmModule } from '../common/services/llm';

@Module({
  imports: [
    MedicationsModule,
    OrganizationsModule,
    EmployeesModule,
    AuthenticationModule,
    LlmModule,
  ],
  controllers: [SchedulingAgentController],
  providers: [McpServerFactory, McpHttpHandlerService, SchedulingAgentService],
  exports: [McpHttpHandlerService],
})
export class McpModule {}
