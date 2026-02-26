import { Module } from '@nestjs/common';
import { MedicationsModule } from '../models/patients/medications/medications.module';
import { OrganizationsModule } from '../models/organizations/organizations.module';
import { AuthenticationModule } from '../authentication/auth.module';
import { McpServerFactory } from './server/mcp-server.factory';
import { McpHttpHandlerService } from './mcp-http-handler.service';

@Module({
  imports: [MedicationsModule, OrganizationsModule, AuthenticationModule],
  providers: [McpServerFactory, McpHttpHandlerService],
  exports: [McpHttpHandlerService],
})
export class McpModule {}
