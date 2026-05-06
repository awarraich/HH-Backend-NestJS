import { Injectable, Logger } from '@nestjs/common';
import { computeCostUsd } from './cost-rates';

/**
 * Per-turn telemetry: starts a timer when the agent begins handling a
 * MESSAGE event, then emits a single structured log line at the end with
 * the assembled fields (latency, cost, tools used, error if any).
 *
 * Intentionally tiny — no Sentry/Prometheus until those are introduced
 * project-wide. The structured log line is the primary observability
 * signal for this module today.
 */
@Injectable()
export class AgentTelemetryService {
  private readonly logger = new Logger(AgentTelemetryService.name);

  /** Open a turn and capture the start time. */
  startTurn(turnId: string): TurnTracker {
    return new TurnTracker(turnId, Date.now());
  }

  /**
   * Compute cost from token counts. Centralised so callers (agent service +
   * transcripts) agree on the cost figure for a given turn.
   */
  costForTurn(
    model: string,
    tokensIn: number,
    tokensOut: number,
  ): number {
    return computeCostUsd(model, tokensIn, tokensOut);
  }

  /** Emit the per-turn structured log line. Always succeeds. */
  recordTurn(snapshot: TurnSnapshot): void {
    try {
      const line = JSON.stringify({
        event: 'agent_turn',
        ...snapshot,
      });
      if (snapshot.error) {
        this.logger.error(line);
      } else {
        this.logger.log(line);
      }
    } catch (err) {
      this.logger.warn(
        `Failed to emit telemetry for turn ${snapshot.turnId}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}

/**
 * Lightweight per-turn timer. Hold one of these between
 * `agentTelemetry.startTurn()` and the end of the pipeline.
 */
export class TurnTracker {
  constructor(
    public readonly turnId: string,
    public readonly startedAtMs: number,
  ) {}

  elapsedMs(): number {
    return Date.now() - this.startedAtMs;
  }
}

/**
 * Shape of one structured log line emitted per turn. Keep field names
 * stable — log aggregators / future dashboards key off them.
 */
export interface TurnSnapshot {
  turnId: string;
  userId?: string;
  organizationId?: string;
  threadKey?: string;
  provider?: 'anthropic' | 'openai' | 'none';
  model?: string;
  toolsCalled: string[];
  tokensIn: number;
  tokensOut: number;
  costUsd: number;
  latencyMs: number;
  /** Outcome shorthand: success / error / disabled / unlinked / slash / empty. */
  outcome:
    | 'success'
    | 'error'
    | 'disabled'
    | 'unlinked'
    | 'slash'
    | 'empty'
    | 'attachment_only'
    | 'context_missing';
  error?: string;
}
