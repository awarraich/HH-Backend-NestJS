import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppSettingsService } from '../settings/app-settings.service';
import { OpenAiLlmProvider } from './openai-llm.provider';
import { BedrockLlmProvider } from './bedrock-llm.provider';
import type { LlmProvider } from './llm-provider.interface';
import type { LlmGenerateOptions, LlmGenerateResult } from './llm.types';

export type LlmProviderName = 'openai' | 'bedrock';

export interface LlmRoutingContext {
  /** Resolves a per-org override; falls back to global / env / 'openai'. */
  organizationId?: string | null;
}

const LLM_PROVIDER_KEY = 'llm.provider';

@Injectable()
export class LlmRouter {
  private readonly logger = new Logger(LlmRouter.name);

  constructor(
    private readonly openai: OpenAiLlmProvider,
    private readonly bedrock: BedrockLlmProvider,
    private readonly settings: AppSettingsService,
    private readonly config: ConfigService,
  ) {}

  async generate(
    options: LlmGenerateOptions,
    context?: LlmRoutingContext,
  ): Promise<LlmGenerateResult> {
    const provider = await this.resolve(context?.organizationId);
    this.logger.log(
      `route → ${provider.name}${context?.organizationId ? ` (org=${context.organizationId})` : ' (no org)'}`,
    );
    return provider.generate(options);
  }

  /**
   * Returns the active provider's name without invoking it. Used by callers
   * that need to decide whether to forward an OpenAI-specific model name
   * (the Bedrock provider ignores it and uses its own modelId regardless).
   */
  async resolveName(organizationId?: string | null): Promise<LlmProviderName> {
    const provider = await this.resolve(organizationId);
    return provider.name;
  }

  private async resolve(organizationId?: string | null): Promise<LlmProvider> {
    const value = await this.settings.getResolvedValue<string>(
      LLM_PROVIDER_KEY,
      organizationId ?? null,
    );
    const fromDb = normalize(value);
    if (fromDb) return this.byName(fromDb);

    const fromEnv = normalize(this.config.get<string>('llm.provider'));
    if (fromEnv) return this.byName(fromEnv);

    return this.openai;
  }

  private byName(name: LlmProviderName): LlmProvider {
    if (name === 'openai') return this.openai;
    if (name === 'bedrock') return this.bedrock;
    this.logger.warn(`Unknown LLM provider name "${name}"; falling back to openai`);
    return this.openai;
  }
}

function normalize(raw: string | null | undefined): LlmProviderName | null {
  if (!raw) return null;
  const lowered = String(raw).trim().toLowerCase();
  if (lowered === 'openai' || lowered === 'bedrock') return lowered;
  return null;
}
