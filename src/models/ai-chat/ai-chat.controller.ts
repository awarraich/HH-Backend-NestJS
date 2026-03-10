import { Controller, Get, Query, UseGuards, HttpCode, HttpStatus } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';

/**
 * Stub controller for the legacy ai-chat sidebar (user-chats list).
 * Returns an empty list so the frontend does not 404. Full AI chat can be implemented later.
 */
@Controller('v1/api/ai-chat')
@UseGuards(JwtAuthGuard)
export class AiChatController {
  @Get('user-chats')
  @HttpCode(HttpStatus.OK)
  getUserChats(@Query('page') _page?: string): { chatsList: never[]; has_more: boolean } {
    return {
      chatsList: [],
      has_more: false,
    };
  }
}
