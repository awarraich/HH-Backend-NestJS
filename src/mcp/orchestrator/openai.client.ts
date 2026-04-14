import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import OpenAI from 'openai';

@Injectable()
export class OpenAiClient implements OnModuleInit {
  private readonly logger = new Logger(OpenAiClient.name);
  readonly client: OpenAI;

  constructor() {
    this.client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  }

  onModuleInit() {
    if (!process.env.OPENAI_API_KEY) {
      this.logger.warn(
        'OPENAI_API_KEY is not set — scheduling agent calls will fail at runtime.',
      );
    }
  }
}
