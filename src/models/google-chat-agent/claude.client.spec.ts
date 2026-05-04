import { ClaudeClient } from './claude.client';
import { GoogleChatAgentConfigService } from '../../config/google-chat-agent/config.service';
import type { AgentLlmProvider } from '../../config/google-chat-agent/configuration';

const buildConfig = (
  overrides: Partial<{
    enabled: boolean;
    provider: AgentLlmProvider;
    anthropicApiKey: string;
    openaiApiKey: string;
  }> = {},
): GoogleChatAgentConfigService =>
  ({
    enabled: overrides.enabled ?? false,
    provider: overrides.provider ?? 'anthropic',
    anthropicApiKey: overrides.anthropicApiKey ?? '',
    openaiApiKey: overrides.openaiApiKey ?? '',
    model: 'claude-sonnet-4-5-20250929',
    triageModel: 'claude-haiku-4-5-20251001',
    maxTokens: 2048,
    turnTimeoutMs: 30000,
    freeMessagesPerUser: 50,
  }) as unknown as GoogleChatAgentConfigService;

describe('ClaudeClient (M1) — Anthropic provider', () => {
  it('initializes the Anthropic client when enabled with key', () => {
    const c = new ClaudeClient(
      buildConfig({
        enabled: true,
        provider: 'anthropic',
        anthropicApiKey: 'sk-ant-test',
      }),
    );
    expect(c.isEnabled()).toBe(true);
    expect(c.provider).toBe('anthropic');
    expect(c.getAnthropic()).toBeDefined();
    // getClient() is the legacy alias — should work for anthropic.
    expect(c.getClient()).toBeDefined();
    // OpenAI accessor should throw because we're on the anthropic path.
    expect(() => c.getOpenAI()).toThrow(/not openai/i);
  });

  it('throws when provider=anthropic but ANTHROPIC_API_KEY missing', () => {
    expect(
      () =>
        new ClaudeClient(
          buildConfig({
            enabled: true,
            provider: 'anthropic',
            anthropicApiKey: '',
          }),
        ),
    ).toThrow(/ANTHROPIC_API_KEY/);
  });
});

describe('ClaudeClient — OpenAI provider', () => {
  it('initializes the OpenAI client when enabled with key', () => {
    const c = new ClaudeClient(
      buildConfig({
        enabled: true,
        provider: 'openai',
        openaiApiKey: 'sk-openai-test',
      }),
    );
    expect(c.isEnabled()).toBe(true);
    expect(c.provider).toBe('openai');
    expect(c.getOpenAI()).toBeDefined();
    // Anthropic accessor (and its legacy alias) should throw on this path.
    expect(() => c.getAnthropic()).toThrow(/not anthropic/i);
    expect(() => c.getClient()).toThrow(/not anthropic/i);
  });

  it('throws when provider=openai but OPENAI_API_KEY missing', () => {
    expect(
      () =>
        new ClaudeClient(
          buildConfig({
            enabled: true,
            provider: 'openai',
            openaiApiKey: '',
          }),
        ),
    ).toThrow(/OPENAI_API_KEY/);
  });
});

describe('ClaudeClient — disabled state', () => {
  it('is a no-op when disabled (anthropic provider, no key)', () => {
    const c = new ClaudeClient(
      buildConfig({
        enabled: false,
        provider: 'anthropic',
        anthropicApiKey: '',
      }),
    );
    expect(c.isEnabled()).toBe(false);
    expect(c.provider).toBe('none');
    expect(() => c.getAnthropic()).toThrow();
    expect(() => c.getOpenAI()).toThrow();
  });

  it('is a no-op when disabled (openai provider, no key)', () => {
    const c = new ClaudeClient(
      buildConfig({
        enabled: false,
        provider: 'openai',
        openaiApiKey: '',
      }),
    );
    expect(c.isEnabled()).toBe(false);
    expect(c.provider).toBe('none');
  });
});
