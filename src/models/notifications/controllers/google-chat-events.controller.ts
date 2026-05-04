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

@Controller('webhooks/google-chat')
export class GoogleChatEventsController {
  private readonly logger = new Logger(GoogleChatEventsController.name);

  constructor(private readonly handler: BotEventHandlerService) {}

  @Get('events')
  @HttpCode(HttpStatus.OK)
  health(): { ok: true; service: string } {
    return { ok: true, service: 'google-chat-webhook' };
  }

  @Post('events')
  @UseGuards(GoogleChatRequestGuard)
  @HttpCode(HttpStatus.OK)
  async handleEvent(@Body() event: GoogleChatEventPayload): Promise<object> {
    this.logger.log(`Received Google Chat event: ${event?.type ?? 'unknown'}`);

    if (event?.type === 'ADDED_TO_SPACE') {
      return await this.handler.handleAddedToSpace(event);
    }

    if (event?.type === 'REMOVED_FROM_SPACE') {
      await this.handler.handleRemovedFromSpace(event);
      return {};
    }

    if (event?.type === 'MESSAGE') {
      return this.handler.handleMessage();
    }

    return {};
  }
}
