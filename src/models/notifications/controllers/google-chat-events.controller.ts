import {
  Controller,
  Post,
  Body,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  UseGuards,
} from '@nestjs/common';
import { GoogleChatRequestGuard } from '../guards/google-chat-request.guard';
import { BotEventHandlerService } from '../services/bot-event-handler.service';
import type { GoogleChatEventPayload } from '../services/bot-event-handler.service';
import { GoogleChatAgentService } from '../../google-chat-agent/services/google-chat-agent.service';
import type { AgentChatEvent } from '../../google-chat-agent/types/chat-event.types';

@Controller('webhooks/google-chat')
export class GoogleChatEventsController {
  private readonly logger = new Logger(GoogleChatEventsController.name);

  constructor(
    private readonly handler: BotEventHandlerService,
    private readonly agent: GoogleChatAgentService,
  ) {}

  @Get('events')
  @HttpCode(HttpStatus.OK)
  health(): { ok: true; service: string } {
    return { ok: true, service: 'google-chat-webhook' };
  }

  @Post('events')
  @UseGuards(GoogleChatRequestGuard)
  @HttpCode(HttpStatus.OK)
  async handleEvent(
    @Body() event: GoogleChatEventPayload & AgentChatEvent,
  ): Promise<object> {
    this.logger.log(`Received Google Chat event: ${event?.type ?? 'unknown'}`);

    if (event?.type === 'ADDED_TO_SPACE') {
      return await this.handler.handleAddedToSpace(event);
    }

    if (event?.type === 'REMOVED_FROM_SPACE') {
      await this.handler.handleRemovedFromSpace(event);
      return {};
    }

    if (event?.type === 'MESSAGE') {
      // When the agent is enabled (global flag + Anthropic key configured),
      // route MESSAGE events through the scheduling agent. Otherwise fall
      // back to the legacy "notifications-only" stub for compatibility.
      if (this.agent.isEnabled()) {
        return await this.agent.handleMessage(event);
      }
      return this.handler.handleMessage();
    }

    return {};
  }
}
