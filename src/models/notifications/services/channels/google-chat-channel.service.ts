import { Injectable, Logger } from '@nestjs/common';
import { GoogleChatClientService } from '../google-chat-client.service';

@Injectable()
export class GoogleChatChannelService {
  private readonly logger = new Logger(GoogleChatChannelService.name);

  constructor(private readonly chatClient: GoogleChatClientService) {}

  async sendDirectMessage(dmSpaceName: string, text: string): Promise<void> {
    if (!this.chatClient.isAvailable()) {
      throw new Error('Google Chat client not available — check service account config');
    }

    const client = this.chatClient.getClient();
    await client.spaces.messages.create({
      parent: dmSpaceName,
      requestBody: { text },
    });

    this.logger.log(`Sent DM to ${dmSpaceName}`);
  }

  /**
   * Removes the bot from a Chat space (e.g. user-initiated disconnect).
   * Uses `chat.spaces.members.delete` with the special `members/app` alias
   * which targets the bot's own membership. Callers should treat this as
   * best-effort — a failure here shouldn't block the disconnect from
   * completing on the HomeHealth side.
   */
  async leaveSpace(dmSpaceName: string): Promise<void> {
    if (!this.chatClient.isAvailable()) {
      throw new Error('Google Chat client not available — check service account config');
    }

    const client = this.chatClient.getClient();
    await client.spaces.members.delete({
      name: `${dmSpaceName}/members/app`,
    });

    this.logger.log(`Bot left space ${dmSpaceName}`);
  }
}
