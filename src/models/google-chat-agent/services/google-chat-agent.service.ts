import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type { MessageParam } from '@anthropic-ai/sdk/resources/messages';
import type { ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { ClaudeClient } from '../claude.client';
import { GoogleChatAgentConfigService } from '../../../config/google-chat-agent/config.service';
import { CardRendererRegistry } from '../rendering/renderer.registry';
import { buildDisabledCard } from '../rendering/disabled.card';
import { buildErrorCard } from '../rendering/error.card';
import {
  AgentTelemetryService,
  TurnTracker,
} from '../observability/agent-telemetry.service';
import { ToolRegistry } from '../tools/tool.registry';
import { AgentContext } from '../tools/tool.types';
import { AgentIdentityService } from './agent-identity.service';
import { AgentTranscriptService } from './agent-transcript.service';
import { ConversationStateService } from './conversation-state.service';
import { buildSystemPrompt } from './system-prompt';
import { runToolUseLoop } from './tool-use-loop';
import {
  buildAttachmentReply,
  buildHelpReply,
  buildResetReply,
  buildUnlinkedReply,
  buildWhoAmIReply,
  isSlashCommand,
} from './slash-commands';
import type { AgentChatEvent, AgentReply } from '../types/chat-event.types';
import type { AgentTurn } from './conversation-state.types';

/**
 * Orchestrates a single MESSAGE event from the Google Chat webhook:
 *   1. Disabled / kill-switch check.
 *   2. Identity resolution (Chat user → HH user via M2).
 *   3. Slash-command routing — short-circuit before LLM.
 *   4. Empty / attachment-only fallback.
 *   5. Conversation state load + Claude tool-use loop (M4 + M5 + M9).
 *   6. Render last tool output as a card (M9), or fall back to plain text.
 *   7. Persist user + assistant turns to thread state (M3).
 *
 * Errors anywhere in the pipeline produce an error card with a turnId so
 * support can correlate logs. Errors are caught at the boundary; the
 * webhook always responds with a valid AgentReply.
 */
@Injectable()
export class GoogleChatAgentService {
  private readonly logger = new Logger(GoogleChatAgentService.name);

  constructor(
    private readonly config: GoogleChatAgentConfigService,
    private readonly claude: ClaudeClient,
    private readonly identity: AgentIdentityService,
    private readonly state: ConversationStateService,
    private readonly registry: ToolRegistry,
    private readonly renderers: CardRendererRegistry,
    private readonly transcripts: AgentTranscriptService,
    private readonly telemetry: AgentTelemetryService,
  ) {}

  /**
   * True if the agent is globally enabled. Per-org enable comes with M13;
   * the webhook checks this AND the future per-org flag.
   */
  isEnabled(): boolean {
    return this.config.enabled && this.claude.isEnabled();
  }

  async handleMessage(event: AgentChatEvent): Promise<AgentReply> {
    const turnId = randomUUID();
    const tracker = this.telemetry.startTurn(turnId);

    if (!this.isEnabled()) {
      this.telemetry.recordTurn({
        turnId,
        provider: this.claude.provider,
        toolsCalled: [],
        tokensIn: 0,
        tokensOut: 0,
        costUsd: 0,
        latencyMs: tracker.elapsedMs(),
        outcome: 'disabled',
        threadKey: resolveConversationKey(event) ?? undefined,
      });
      return buildDisabledCard();
    }

    try {
      return await this.runPipeline(event, turnId, tracker);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `[turn=${turnId}] Unhandled error in agent pipeline: ${message}`,
        err instanceof Error ? err.stack : undefined,
      );

      // Best-effort error transcript when identity was resolvable; fail
      // silently if not (no org/user to key the row on).
      try {
        const chatUserId = event.user?.name;
        const threadName = resolveConversationKey(event);
        if (chatUserId && threadName) {
          const user = await this.identity.resolve(chatUserId);
          if (user) {
            await this.transcripts.recordTurn({
              organizationId: user.organizationId,
              userId: user.userId,
              threadName,
              role: 'system',
              payload: { kind: 'pipeline_error', error: message, turnId },
              countsAgainstQuota: false,
            });
          }
        }
      } catch {
        // swallow — transcript writes never block the user reply
      }

      this.telemetry.recordTurn({
        turnId,
        provider: this.claude.provider,
        threadKey: resolveConversationKey(event) ?? undefined,
        toolsCalled: [],
        tokensIn: 0,
        tokensOut: 0,
        costUsd: 0,
        latencyMs: tracker.elapsedMs(),
        outcome: 'error',
        error: message,
      });

      return buildErrorCard({ errorId: turnId });
    }
  }

  private async runPipeline(
    event: AgentChatEvent,
    turnId: string,
    tracker: TurnTracker,
  ): Promise<AgentReply> {
    const chatUserId = event.user?.name;
    const threadName = resolveConversationKey(event);

    if (!chatUserId || !threadName) {
      this.telemetry.recordTurn({
        turnId,
        provider: this.claude.provider,
        toolsCalled: [],
        tokensIn: 0,
        tokensOut: 0,
        costUsd: 0,
        latencyMs: tracker.elapsedMs(),
        outcome: 'context_missing',
      });
      return { text: 'Missing user or thread context — please retry.' };
    }

    const user = await this.identity.resolve(chatUserId);
    if (!user) {
      this.telemetry.recordTurn({
        turnId,
        provider: this.claude.provider,
        threadKey: threadName,
        toolsCalled: [],
        tokensIn: 0,
        tokensOut: 0,
        costUsd: 0,
        latencyMs: tracker.elapsedMs(),
        outcome: 'unlinked',
      });
      return buildUnlinkedReply();
    }

    const rawText = (event.message?.text ?? event.message?.argumentText ?? '').trim();
    const hasAttachments = (event.message?.attachment ?? []).length > 0;

    // Slash commands bypass the LLM and don't count against quota.
    if (isSlashCommand(rawText)) {
      const cmd = rawText.toLowerCase();
      await this.transcripts.recordTurn({
        organizationId: user.organizationId,
        userId: user.userId,
        threadName,
        role: 'system',
        toolName: cmd,
        payload: { kind: 'slash_command', command: cmd, turnId },
        countsAgainstQuota: false,
      });
      const slashReply: AgentReply | null =
        cmd === '/help'
          ? buildHelpReply()
          : cmd === '/whoami'
            ? buildWhoAmIReply(user)
            : cmd === '/reset'
              ? (await this.state.clear(threadName), buildResetReply())
              : null;
      if (slashReply) {
        this.telemetry.recordTurn({
          turnId,
          userId: user.userId,
          organizationId: user.organizationId,
          threadKey: threadName,
          provider: this.claude.provider,
          toolsCalled: [cmd],
          tokensIn: 0,
          tokensOut: 0,
          costUsd: 0,
          latencyMs: tracker.elapsedMs(),
          outcome: 'slash',
        });
        return slashReply;
      }
    }

    if (!rawText) {
      await this.transcripts.recordTurn({
        organizationId: user.organizationId,
        userId: user.userId,
        threadName,
        role: 'system',
        payload: {
          kind: hasAttachments ? 'attachment_only' : 'empty_text',
          turnId,
        },
        countsAgainstQuota: false,
      });
      this.telemetry.recordTurn({
        turnId,
        userId: user.userId,
        organizationId: user.organizationId,
        threadKey: threadName,
        provider: this.claude.provider,
        toolsCalled: [],
        tokensIn: 0,
        tokensOut: 0,
        costUsd: 0,
        latencyMs: tracker.elapsedMs(),
        outcome: hasAttachments ? 'attachment_only' : 'empty',
      });
      return hasAttachments
        ? buildAttachmentReply()
        : { text: 'I didn\'t catch a question — please try again with text.' };
    }

    const ctx: AgentContext = { user, turnId };
    const history = await this.state.get(threadName);
    const systemPrompt = buildSystemPrompt(user);

    // 1. Record the user's turn (counts against quota — this is a real prompt).
    await this.transcripts.recordTurn({
      organizationId: user.organizationId,
      userId: user.userId,
      threadName,
      role: 'user',
      payload: { text: rawText, turnId },
      countsAgainstQuota: true,
    });

    const result = await (this.claude.provider === 'openai'
      ? runToolUseLoop({
          provider: 'openai',
          client: this.claude.getOpenAI(),
          model: this.config.model,
          maxTokens: this.config.maxTokens,
          systemPrompt,
          history: this.toOpenAIHistory(history),
          userText: rawText,
          ctx,
          registry: this.registry,
          tools: this.registry.getOpenAIToolsPayload(),
          logger: this.logger,
        })
      : runToolUseLoop({
          provider: 'anthropic',
          client: this.claude.getAnthropic(),
          model: this.config.model,
          maxTokens: this.config.maxTokens,
          systemPrompt,
          history: this.toAnthropicHistory(history),
          userText: rawText,
          ctx,
          registry: this.registry,
          tools: this.registry.getAnthropicToolsPayload(),
          logger: this.logger,
        }));

    // 2. Record each tool dispatch as its own row.
    for (const tc of result.toolCalls) {
      await this.transcripts.recordTurn({
        organizationId: user.organizationId,
        userId: user.userId,
        threadName,
        role: 'tool',
        toolName: tc.name,
        payload: {
          ok: tc.ok,
          input: tc.input,
          output: tc.output,
          error: tc.error,
          turnId,
        },
        countsAgainstQuota: false,
      });
    }

    // 3. Record the assistant's final reply with aggregated token counts.
    const costUsd = this.telemetry.costForTurn(
      this.config.model,
      result.tokensIn,
      result.tokensOut,
    );
    await this.transcripts.recordTurn({
      organizationId: user.organizationId,
      userId: user.userId,
      threadName,
      role: 'assistant',
      payload: {
        text: result.text,
        provider: this.claude.provider,
        model: this.config.model,
        toolCallSummary: result.toolCalls.map((t) => ({
          name: t.name,
          ok: t.ok,
        })),
        turnId,
      },
      tokensIn: result.tokensIn,
      tokensOut: result.tokensOut,
      costUsd,
      countsAgainstQuota: false, // user turn already counted
    });

    // Append turns to the thread state (text only — tool blocks not retained).
    const now = new Date().toISOString();
    await this.state.append(threadName, {
      role: 'user',
      content: rawText,
      ts: now,
    });
    await this.state.append(threadName, {
      role: 'assistant',
      content: result.text,
      ts: now,
    });

    // Telemetry: success turn — captures the actual cost figure used for the
    // assistant transcript so the log line and the DB row agree.
    this.telemetry.recordTurn({
      turnId,
      userId: user.userId,
      organizationId: user.organizationId,
      threadKey: threadName,
      provider: this.claude.provider,
      model: this.config.model,
      toolsCalled: result.toolCalls.map((t) => t.name),
      tokensIn: result.tokensIn,
      tokensOut: result.tokensOut,
      costUsd,
      latencyMs: tracker.elapsedMs(),
      outcome: 'success',
    });

    // Render last tool output as a card if a renderer exists; otherwise text.
    if (result.lastToolName && result.lastToolOutput !== null) {
      const card = this.renderers.render(
        result.lastToolName,
        result.lastToolOutput,
        result.text,
      );
      if (card) return card;
    }
    return { text: result.text };
  }

  /** Converts our stored turns to Anthropic's MessageParam shape. */
  private toAnthropicHistory(turns: AgentTurn[]): MessageParam[] {
    return turns
      .filter((t): t is AgentTurn & { role: 'user' | 'assistant' } =>
        t.role === 'user' || t.role === 'assistant',
      )
      .map((t) => ({
        role: t.role,
        content: typeof t.content === 'string' ? t.content : JSON.stringify(t.content),
      }));
  }

  /** Converts our stored turns to OpenAI's ChatCompletionMessageParam shape. */
  private toOpenAIHistory(turns: AgentTurn[]): ChatCompletionMessageParam[] {
    return turns
      .filter((t): t is AgentTurn & { role: 'user' | 'assistant' } =>
        t.role === 'user' || t.role === 'assistant',
      )
      .map((t) => ({
        role: t.role,
        content:
          typeof t.content === 'string'
            ? t.content
            : JSON.stringify(t.content),
      }));
  }
}

/**
 * Resolves the conversation-state key for a Chat event.
 *
 * In a 1:1 DM with `spaceThreadingState: THREADED_MESSAGES` (the default
 * for new bot DMs), every top-level user message gets a fresh `thread.name`.
 * Keying state on `thread.name` would discard prior context on every new
 * top-level message — observed bug: turn 1 "set Tuesday 9-5", turn 2 "Yes"
 * arrived in a different thread.name and the agent had no context to act on.
 *
 * Strategy:
 *   - DM (`space.type === 'DM'` or `singleUserBotDm`): key on `space.name`.
 *     A 1:1 DM is one logical conversation regardless of Chat's threading.
 *   - Room (`space.type === 'ROOM'`): key on `thread.name` so independent
 *     topic threads keep separate state.
 *
 * Falls back gracefully if fields are missing.
 */
export function resolveConversationKey(
  event: AgentChatEvent,
): string | null {
  const spaceName = event.space?.name ?? null;
  const threadName = event.message?.thread?.name ?? null;

  const isDm =
    event.space?.type === 'DM' ||
    event.space?.singleUserBotDm === true ||
    event.space?.spaceType === 'DIRECT_MESSAGE';

  if (isDm) return spaceName;
  return threadName ?? spaceName;
}
