import type { LlmGenerateOptions, LlmGenerateResult } from './llm.types';

export interface LlmProvider {
  readonly name: 'openai' | 'bedrock';
  generate(options: LlmGenerateOptions): Promise<LlmGenerateResult>;
}
