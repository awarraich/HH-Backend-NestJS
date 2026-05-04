import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { GoogleChatAgentConfigService } from '../../../config/google-chat-agent/config.service';
import {
  AgentChatTranscript,
  TranscriptRole,
} from '../entities/agent-chat-transcript.entity';
import { redactPayload } from './pii-redaction';

export interface RecordTurnInput {
  organizationId: string;
  userId: string;
  threadName: string;
  role: TranscriptRole;
  payload: Record<string, unknown>;
  toolName?: string | null;
  tokensIn?: number | null;
  tokensOut?: number | null;
  costUsd?: number | null;
  countsAgainstQuota?: boolean;
}

/**
 * Writes one row per agent turn to `agent_chat_transcripts`.
 *
 * Contract: NEVER throws. A failure to write a transcript must not block
 * the user reply or the rest of the pipeline. Failures are logged at
 * warn-level and dropped. (M11-I1.)
 *
 * The write computes `turn_index` as MAX(turn_index)+1 per thread inside
 * a single SQL statement. There's a tiny race window if two webhook
 * requests for the same thread land within milliseconds, but per-thread
 * concurrency is realistically zero (one user, sequential webhook calls
 * per thread). The unique constraint catches it if it ever happens.
 */
@Injectable()
export class AgentTranscriptService {
  private readonly logger = new Logger(AgentTranscriptService.name);

  constructor(
    @InjectRepository(AgentChatTranscript)
    private readonly repo: Repository<AgentChatTranscript>,
    private readonly config: GoogleChatAgentConfigService,
  ) {}

  async recordTurn(input: RecordTurnInput): Promise<void> {
    try {
      const payload = this.config.piiRedaction
        ? (redactPayload(input.payload) as Record<string, unknown>)
        : input.payload;

      // Atomic-ish nextTurnIndex: SELECT MAX inside the INSERT via a CTE.
      // We use the underlying QueryBuilder rather than a TypeORM-managed
      // entity insert because the `turn_index` value depends on existing rows.
      await this.repo.query(
        `INSERT INTO agent_chat_transcripts
           (organization_id, user_id, chat_thread_name, turn_index, role, tool_name,
            payload, tokens_in, tokens_out, cost_usd, counts_against_quota)
         VALUES (
           $1, $2, $3,
           COALESCE((SELECT MAX(turn_index) FROM agent_chat_transcripts
                     WHERE chat_thread_name = $3), -1) + 1,
           $4, $5, $6, $7, $8, $9, $10
         )`,
        [
          input.organizationId,
          input.userId,
          input.threadName,
          input.role,
          input.toolName ?? null,
          JSON.stringify(payload),
          input.tokensIn ?? null,
          input.tokensOut ?? null,
          input.costUsd ?? null,
          input.countsAgainstQuota ?? true,
        ],
      );
    } catch (err) {
      this.logger.warn(
        `Failed to record transcript turn (thread=${input.threadName}, role=${input.role}): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  async listForThread(threadName: string): Promise<AgentChatTranscript[]> {
    return this.repo.find({
      where: { chat_thread_name: threadName },
      order: { turn_index: 'ASC' },
    });
  }

  async countForUser(
    organizationId: string,
    userId: string,
  ): Promise<number> {
    return this.repo.count({
      where: {
        organization_id: organizationId,
        user_id: userId,
        counts_against_quota: true,
      },
    });
  }
}
