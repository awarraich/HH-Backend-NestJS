import { GoogleChatAgentService } from './google-chat-agent.service';
import { ClaudeClient } from '../claude.client';
import { AgentIdentityService } from './agent-identity.service';
import { AgentTranscriptService } from './agent-transcript.service';
import { ConversationStateService } from './conversation-state.service';
import { ToolRegistry } from '../tools/tool.registry';
import { CardRendererRegistry } from '../rendering/renderer.registry';
import { GoogleChatAgentConfigService } from '../../../config/google-chat-agent/config.service';
import type { AgentChatEvent } from '../types/chat-event.types';
import type { ResolvedAgentUser } from './agent-identity.types';

const fakeUser = (
  overrides: Partial<ResolvedAgentUser> = {},
): ResolvedAgentUser => ({
  userId: 'user-uuid-1',
  organizationId: 'org-uuid-1',
  timezone: 'UTC',
  chatUserId: 'users/123',
  chatSpaceName: 'spaces/AAA',
  ...overrides,
});

const buildService = (
  overrides: {
    enabled?: boolean;
    claudeEnabled?: boolean;
    resolveResult?: ResolvedAgentUser | null;
    runLoopText?: string;
    lastToolName?: string | null;
    lastToolOutput?: unknown;
    rendererForTool?: string | null;
  } = {},
) => {
  const config = {
    enabled: overrides.enabled ?? true,
    model: 'claude-sonnet-4-5-20250929',
    maxTokens: 2048,
  } as unknown as GoogleChatAgentConfigService;

  const claude = {
    isEnabled: () => overrides.claudeEnabled ?? true,
    getClient: () =>
      ({
        messages: { create: jest.fn() },
      }) as unknown as Parameters<typeof ClaudeClient.prototype.getClient>[0],
  } as unknown as ClaudeClient;

  const identity = {
    resolve: jest
      .fn()
      .mockResolvedValue(
        overrides.resolveResult === undefined
          ? fakeUser()
          : overrides.resolveResult,
      ),
  } as unknown as AgentIdentityService;

  const stateGet = jest.fn().mockResolvedValue([]);
  const stateAppend = jest.fn().mockResolvedValue(undefined);
  const stateClear = jest.fn().mockResolvedValue(undefined);
  const state = {
    get: stateGet,
    append: stateAppend,
    clear: stateClear,
  } as unknown as ConversationStateService;

  const registry = {
    getAnthropicToolsPayload: jest.fn().mockReturnValue([]),
  } as unknown as ToolRegistry;

  const renderers = {
    render: jest.fn().mockImplementation((toolName: string) => {
      if (overrides.rendererForTool && toolName === overrides.rendererForTool) {
        return { cardsV2: [{ cardId: 'fake', card: { sections: [] } }] };
      }
      return null;
    }),
  } as unknown as CardRendererRegistry;

  const transcripts = {
    recordTurn: jest.fn().mockResolvedValue(undefined),
    listForThread: jest.fn().mockResolvedValue([]),
    countForUser: jest.fn().mockResolvedValue(0),
  } as unknown as AgentTranscriptService;

  const service = new GoogleChatAgentService(
    config,
    claude,
    identity,
    state,
    registry,
    renderers,
    transcripts,
  );

  // Stub the runPipeline -> runToolUseLoop interaction by patching the
  // import via jest.mock at top-level would be too coarse; instead we
  // monkey-patch the prototype method `toAnthropicHistory` only when the
  // tests actually need to exercise the LLM loop. For tests that don't
  // hit the loop (disabled/slash/attachment), we never reach there.
  return { service, config, claude, identity, state, registry, renderers, transcripts };
};

const event = (overrides: Partial<AgentChatEvent> = {}): AgentChatEvent => ({
  type: 'MESSAGE',
  user: { name: 'users/123', email: 'sara@example.com' },
  space: { name: 'spaces/AAA' },
  message: { text: 'hi', thread: { name: 'spaces/AAA/threads/T1' } },
  ...overrides,
});

describe('GoogleChatAgentService.handleMessage (M8)', () => {
  // M8-U1 (regression): ADDED_TO_SPACE not handled here; verified by separate
  // notification-module test. This service only handles MESSAGE.

  // M8-U4: Disabled flag returns the disabled card without invoking Claude.
  it('returns the disabled card when global flag is off', async () => {
    const { service, identity } = buildService({ enabled: false });
    const reply = await service.handleMessage(event());
    expect('cardsV2' in reply ? reply.cardsV2[0].cardId : '').toBe(
      'agent-disabled',
    );
    expect((identity.resolve as jest.Mock).mock.calls.length).toBe(0);
  });

  it('returns the disabled card when Claude client is not initialized', async () => {
    const { service } = buildService({ claudeEnabled: false });
    const reply = await service.handleMessage(event());
    expect('cardsV2' in reply ? reply.cardsV2[0].cardId : '').toBe(
      'agent-disabled',
    );
  });

  it('returns an unlinked reply when identity resolution fails', async () => {
    const { service } = buildService({ resolveResult: null });
    const reply = await service.handleMessage(event());
    expect('text' in reply ? reply.text : '').toMatch(/don.?t recognise/i);
  });

  it('returns a context-missing reply when chatUserId or thread is absent', async () => {
    const { service } = buildService();
    const reply = await service.handleMessage({
      type: 'MESSAGE',
      user: {},
      space: {},
      message: { text: 'hi' },
    });
    expect('text' in reply ? reply.text : '').toMatch(/missing/i);
  });

  // M8-U2: MESSAGE with attachments and no text → attachment fallback.
  it('returns the attachment fallback when message has attachment but no text', async () => {
    const { service } = buildService();
    const reply = await service.handleMessage(
      event({
        message: {
          text: '',
          thread: { name: 'spaces/AAA/threads/T1' },
          attachment: [{ name: 'attachments/abc' }],
        },
      }),
    );
    expect('text' in reply ? reply.text : '').toMatch(/can.?t read attachments/i);
  });

  it('returns a no-text reply when message is empty and has no attachment', async () => {
    const { service } = buildService();
    const reply = await service.handleMessage(
      event({ message: { text: '   ', thread: { name: 'spaces/AAA/threads/T1' } } }),
    );
    expect('text' in reply ? reply.text : '').toMatch(/didn.?t catch/i);
  });

  describe('slash commands', () => {
    it('routes /help without invoking Claude', async () => {
      const { service, registry } = buildService();
      const reply = await service.handleMessage(
        event({ message: { text: '/help', thread: { name: 'spaces/AAA/threads/T1' } } }),
      );
      expect('text' in reply ? reply.text : '').toMatch(/Scheduling assistant/i);
      expect(
        (registry.getAnthropicToolsPayload as jest.Mock).mock.calls.length,
      ).toBe(0);
    });

    it('routes /whoami with the resolved user details', async () => {
      const { service } = buildService();
      const reply = await service.handleMessage(
        event({ message: { text: '/whoami', thread: { name: 'spaces/AAA/threads/T1' } } }),
      );
      const text = 'text' in reply ? reply.text : '';
      expect(text).toContain('user-uuid-1');
      expect(text).toContain('org-uuid-1');
    });

    // M8-U3: /reset clears the thread state (calls state.clear).
    it('routes /reset, calls state.clear with the thread name, and returns the reset confirmation', async () => {
      const { service, state } = buildService();
      const reply = await service.handleMessage(
        event({ message: { text: '/reset', thread: { name: 'spaces/AAA/threads/RESET' } } }),
      );
      expect('text' in reply ? reply.text : '').toMatch(/cleared/i);
      expect(state.clear).toHaveBeenCalledWith('spaces/AAA/threads/RESET');
    });

    it('is case-insensitive for slash commands', async () => {
      const { service } = buildService();
      const reply = await service.handleMessage(
        event({ message: { text: '/HELP', thread: { name: 'spaces/AAA/threads/T1' } } }),
      );
      expect('text' in reply ? reply.text : '').toMatch(/Scheduling assistant/i);
    });
  });

  describe('isEnabled()', () => {
    it('reflects both the config flag and the Claude client state', () => {
      const { service: a } = buildService({ enabled: true, claudeEnabled: true });
      const { service: b } = buildService({ enabled: false, claudeEnabled: true });
      const { service: c } = buildService({ enabled: true, claudeEnabled: false });
      expect(a.isEnabled()).toBe(true);
      expect(b.isEnabled()).toBe(false);
      expect(c.isEnabled()).toBe(false);
    });
  });

  describe('transcript hooks (M11)', () => {
    it('records a system row for slash commands with countsAgainstQuota=false', async () => {
      const { service, transcripts } = buildService();
      await service.handleMessage(
        event({
          message: { text: '/help', thread: { name: 'spaces/AAA/threads/T1' } },
        }),
      );
      expect(transcripts.recordTurn).toHaveBeenCalledWith(
        expect.objectContaining({
          role: 'system',
          countsAgainstQuota: false,
          toolName: '/help',
        }),
      );
    });

    it('records a system row for attachment fallback', async () => {
      const { service, transcripts } = buildService();
      await service.handleMessage(
        event({
          message: {
            text: '',
            thread: { name: 'spaces/AAA/threads/T1' },
            attachment: [{ name: 'attachments/abc' }],
          },
        }),
      );
      expect(transcripts.recordTurn).toHaveBeenCalledWith(
        expect.objectContaining({
          role: 'system',
          countsAgainstQuota: false,
          payload: expect.objectContaining({ kind: 'attachment_only' }),
        }),
      );
    });

    it('does NOT call transcripts on the disabled-card path (no identity yet)', async () => {
      const { service, transcripts } = buildService({ enabled: false });
      await service.handleMessage(event());
      expect(transcripts.recordTurn).not.toHaveBeenCalled();
    });

    it('does NOT call transcripts when identity resolution fails', async () => {
      const { service, transcripts } = buildService({ resolveResult: null });
      await service.handleMessage(event());
      expect(transcripts.recordTurn).not.toHaveBeenCalled();
    });
  });
});
