import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { GoogleChatAgentConfigModule } from '../../config/google-chat-agent/config.module';
import { UserChatConnection } from '../notifications/entities/user-chat-connection.entity';
import { OrganizationsModule } from '../organizations/organizations.module';
import { EmployeesModule } from '../employees/employees.module';
import { AgentChatTranscript } from './entities/agent-chat-transcript.entity';
import { ClaudeClient } from './claude.client';
import { AgentIdentityService } from './services/agent-identity.service';
import { AgentTranscriptService } from './services/agent-transcript.service';
import {
  AgentRedisClient,
  agentRedisClientProvider,
} from './redis/agent-redis.client';
import { ConversationStateService } from './services/conversation-state.service';
import { GoogleChatAgentService } from './services/google-chat-agent.service';
import { ToolRegistry } from './tools/tool.registry';
import { ShiftToolsProvider } from './tools/shifts/shift-tools.provider';
import { AvailabilityToolsProvider } from './tools/availability/availability-tools.provider';
import { CardRendererRegistry } from './rendering/renderer.registry';
import { ShiftRenderersProvider } from './rendering/shifts/shift-renderers.provider';
import { AvailabilityRenderersProvider } from './rendering/availability/availability-renderers.provider';
import { AgentTelemetryService } from './observability/agent-telemetry.service';

/**
 * Google Chat Scheduling Agent — employee-facing conversational bot
 * delivered through the existing Google Chat webhook.
 *
 * This module is intentionally isolated from src/mcp/ (the org-end AI agent)
 * and from src/common/services/llm (shared LLM router used by the org agent).
 * See docs/agent-google-chat-bot/backend/agent-google-chat-bot-plan.md.
 */
@Module({
  imports: [
    GoogleChatAgentConfigModule,
    TypeOrmModule.forFeature([UserChatConnection, AgentChatTranscript]),
    OrganizationsModule,
    EmployeesModule,
  ],
  providers: [
    agentRedisClientProvider,
    AgentRedisClient,
    ClaudeClient,
    AgentIdentityService,
    AgentTranscriptService,
    ConversationStateService,
    ToolRegistry,
    ShiftToolsProvider,
    AvailabilityToolsProvider,
    CardRendererRegistry,
    ShiftRenderersProvider,
    AvailabilityRenderersProvider,
    AgentTelemetryService,
    GoogleChatAgentService,
  ],
  exports: [
    ClaudeClient,
    AgentIdentityService,
    AgentTranscriptService,
    ConversationStateService,
    AgentRedisClient,
    ToolRegistry,
    CardRendererRegistry,
    AgentTelemetryService,
    GoogleChatAgentService,
  ],
})
export class GoogleChatAgentModule {}
