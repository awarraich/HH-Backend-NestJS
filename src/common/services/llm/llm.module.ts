import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppSettingsModule } from '../settings/app-settings.module';
import { OpenAiLlmProvider } from './openai-llm.provider';
import { BedrockLlmProvider } from './bedrock-llm.provider';
import { LlmRouter } from './llm.router';

@Module({
  imports: [ConfigModule, AppSettingsModule],
  providers: [OpenAiLlmProvider, BedrockLlmProvider, LlmRouter],
  exports: [LlmRouter],
})
export class LlmModule {}
