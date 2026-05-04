import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserChatConnection } from '../../notifications/entities/user-chat-connection.entity';
import {
  AGENT_DEFAULT_TIMEZONE,
  ResolvedAgentUser,
} from './agent-identity.types';

/**
 * Resolves a Google Chat user.name (the inbound `chat_user_id`) to the
 * HH user, by reading the `user_chat_connections` table owned by the
 * notification module. Single source of truth for "who is asking" — every
 * agent tool reads from this.
 *
 * Returns null when:
 *   - no connection row exists for the chat user, or
 *   - the row's status is anything other than 'connected' (pending or revoked).
 *
 * Does NOT introduce a parallel mapping table. Does NOT reach into src/mcp/
 * or the org-end agent's identity layer.
 */
@Injectable()
export class AgentIdentityService {
  constructor(
    @InjectRepository(UserChatConnection)
    private readonly connections: Repository<UserChatConnection>,
  ) {}

  async resolve(chatUserId: string): Promise<ResolvedAgentUser | null> {
    if (!chatUserId) return null;

    const row = await this.connections.findOne({
      where: {
        chat_user_id: chatUserId,
        provider: 'google_chat',
        status: 'connected',
      },
    });

    if (!row) return null;

    return {
      userId: row.user_id,
      organizationId: row.org_id,
      timezone: AGENT_DEFAULT_TIMEZONE,
      chatUserId: row.chat_user_id ?? chatUserId,
      chatSpaceName: row.dm_space_name,
    };
  }
}
