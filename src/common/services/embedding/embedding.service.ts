import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import OpenAI from 'openai';

@Injectable()
export class EmbeddingService {
  private readonly logger = new Logger(EmbeddingService.name);
  private readonly client: OpenAI | null = null;
  private readonly model: string;
  private readonly provider: string;

  constructor(private configService: ConfigService) {
    this.provider = this.configService.get<string>('embedding.provider')?.toLowerCase() ?? 'none';
    this.model =
      this.configService.get<string>('embedding.model') ??
      process.env.EMBEDDING_MODEL ??
      'text-embedding-3-small';

    if (this.provider === 'openai') {
      const apiKey =
        this.configService.get<string>('apiKeys.openai')?.trim() ||
        process.env.OPENAI_API_KEY?.trim() ||
        '';
      if (apiKey) {
        this.client = new OpenAI({ apiKey });
      } else {
        this.logger.warn(
          'EMBEDDING_PROVIDER=openai but OPENAI_API_KEY not set; embeddings disabled',
        );
      }
    } else {
      this.logger.log(
        'Embedding provider is "none"; pgvector storage only (populate embeddings via PostgresML or other process)',
      );
    }
  }

  /**
   * Generate embedding vector for the given text.
   * Returns null when provider is "none", API key is missing, or the request fails.
   * With provider "none", embeddings are not generated here; use PostgreSQL (e.g. PostgresML) or another process to populate the vector column.
   */
  async embed(text: string): Promise<number[] | null> {
    if (this.provider === 'none' || !this.client) {
      return null;
    }
    const trimmed = text?.trim();
    if (!trimmed) {
      return null;
    }
    try {
      const response = await this.client.embeddings.create({
        model: this.model,
        input: trimmed,
      });
      const embedding = response.data?.[0]?.embedding;
      if (!embedding || !Array.isArray(embedding)) {
        return null;
      }
      return embedding;
    } catch (err) {
      this.logger.error('Embedding request failed', err);
      return null;
    }
  }
}
