import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AgentLlmProvider } from './configuration';

@Injectable()
export class GoogleChatAgentConfigService {
  constructor(private configService: ConfigService) {}

  get enabled(): boolean {
    return this.configService.get<boolean>('googleChatAgent.enabled', false);
  }

  get provider(): AgentLlmProvider {
    return this.configService.get<AgentLlmProvider>(
      'googleChatAgent.provider',
      'anthropic',
    );
  }

  get anthropicApiKey(): string {
    return this.configService.get<string>('apiKeys.anthropic', '');
  }

  get openaiApiKey(): string {
    return this.configService.get<string>('apiKeys.openai', '');
  }

  /** Active model based on `provider`. */
  get model(): string {
    return this.provider === 'openai'
      ? this.configService.get<string>('googleChatAgent.openaiModel', 'gpt-4o')
      : this.configService.get<string>(
          'googleChatAgent.model',
          'claude-sonnet-4-5-20250929',
        );
  }

  /** Active triage (small/cheap) model based on `provider`. */
  get triageModel(): string {
    return this.provider === 'openai'
      ? this.configService.get<string>(
          'googleChatAgent.openaiTriageModel',
          'gpt-4o-mini',
        )
      : this.configService.get<string>(
          'googleChatAgent.triageModel',
          'claude-haiku-4-5-20251001',
        );
  }

  get maxTokens(): number {
    return this.configService.get<number>('googleChatAgent.maxTokens', 2048);
  }

  get turnTimeoutMs(): number {
    return this.configService.get<number>(
      'googleChatAgent.turnTimeoutMs',
      30000,
    );
  }

  get freeMessagesPerUser(): number {
    return this.configService.get<number>(
      'googleChatAgent.freeMessagesPerUser',
      50,
    );
  }

  get piiRedaction(): boolean {
    return this.configService.get<boolean>(
      'googleChatAgent.piiRedaction',
      false,
    );
  }
}
