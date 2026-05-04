import { Injectable, Logger } from '@nestjs/common';
import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { GoogleChatAgentConfigService } from '../../config/google-chat-agent/config.service';
import type { AgentLlmProvider } from '../../config/google-chat-agent/configuration';

/**
 * LLM client wrapper for the agent. Holds either an Anthropic or an
 * OpenAI client based on `GOOGLE_CHAT_AGENT_PROVIDER`. The rest of the
 * agent module (tool-use loop, agent service) consults `provider` and
 * picks the right code path.
 *
 * When the agent is disabled, neither client is constructed and
 * `getAnthropic()` / `getOpenAI()` will throw — callers gate on
 * `isEnabled()` first.
 *
 * The class is named ClaudeClient (and the file is claude.client.ts)
 * for backwards compatibility with M1 wiring. The internal shape is
 * provider-agnostic.
 *
 * Isolated from src/mcp/ and src/common/services/llm by design — see
 * docs/agent-google-chat-bot/backend/agent-google-chat-bot-plan.md (§scope).
 */
@Injectable()
export class ClaudeClient {
  private readonly logger = new Logger(ClaudeClient.name);
  private readonly anthropic: Anthropic | null = null;
  private readonly openai: OpenAI | null = null;
  public readonly provider: AgentLlmProvider | 'none';

  constructor(private readonly config: GoogleChatAgentConfigService) {
    if (!config.enabled) {
      this.provider = 'none';
      this.logger.log(
        'GoogleChatAgent disabled (GOOGLE_CHAT_AGENT_ENABLED=false). LLM client not initialized.',
      );
      return;
    }

    const provider = config.provider;
    if (provider === 'anthropic') {
      const apiKey = config.anthropicApiKey;
      if (!apiKey) {
        throw new Error(
          'GoogleChatAgent is enabled with provider=anthropic but ANTHROPIC_API_KEY is not set.',
        );
      }
      this.anthropic = new Anthropic({ apiKey });
      this.provider = 'anthropic';
      this.logger.log(
        `GoogleChatAgent client initialized (provider=anthropic, model=${config.model}).`,
      );
      return;
    }

    if (provider === 'openai') {
      const apiKey = config.openaiApiKey;
      if (!apiKey) {
        throw new Error(
          'GoogleChatAgent is enabled with provider=openai but OPENAI_API_KEY is not set.',
        );
      }
      this.openai = new OpenAI({ apiKey });
      this.provider = 'openai';
      this.logger.log(
        `GoogleChatAgent client initialized (provider=openai, model=${config.model}).`,
      );
      return;
    }

    throw new Error(`Unknown GOOGLE_CHAT_AGENT_PROVIDER: ${provider as string}`);
  }

  isEnabled(): boolean {
    return this.anthropic !== null || this.openai !== null;
  }

  getAnthropic(): Anthropic {
    if (!this.anthropic) {
      throw new Error(
        'ClaudeClient.getAnthropic() called but provider is not anthropic. Gate on isEnabled() and check provider.',
      );
    }
    return this.anthropic;
  }

  getOpenAI(): OpenAI {
    if (!this.openai) {
      throw new Error(
        'ClaudeClient.getOpenAI() called but provider is not openai. Gate on isEnabled() and check provider.',
      );
    }
    return this.openai;
  }

  /**
   * Backwards-compat alias used by code that pre-dates the provider
   * switch. Returns the Anthropic client when provider=anthropic; throws
   * for any other provider so callers learn they need to update.
   */
  getClient(): Anthropic {
    return this.getAnthropic();
  }
}
