/**
 * Per-model token-to-USD rates, used by AgentTelemetryService to attach a
 * `cost_usd` figure to every assistant turn (M11 transcript column).
 *
 * Rates are public list prices in USD per 1,000,000 tokens. Approximate
 * (vendors update them); intended as a "good enough for dashboards" signal,
 * not for billing. If you tune these, keep the shape and update the
 * fallback comment.
 *
 * Anthropic prompt caching: cached reads are discounted (~10x cheaper) on
 * Anthropic; we don't distinguish them here yet — assistant turns mix
 * cache-creation, cache-read, and fresh tokens. Reported cost_usd will be
 * a slight overestimate when caching kicks in. F-item if it ever matters.
 */

export interface ModelRates {
  /** USD per 1M input tokens. */
  inputPerMillion: number;
  /** USD per 1M output tokens. */
  outputPerMillion: number;
}

const RATES: Record<string, ModelRates> = {
  // OpenAI (Chat Completions list prices, approximate as of late 2025).
  'gpt-4o': { inputPerMillion: 2.5, outputPerMillion: 10 },
  'gpt-4o-mini': { inputPerMillion: 0.15, outputPerMillion: 0.6 },

  // Anthropic (Claude API list prices, approximate). Dashes in the model id
  // include the date suffix for stable lookups.
  'claude-sonnet-4-5-20250929': { inputPerMillion: 3, outputPerMillion: 15 },
  'claude-haiku-4-5-20251001': { inputPerMillion: 1, outputPerMillion: 5 },
};

/** Fallback rate used when a model id isn't in the table — log a warning once. */
const FALLBACK: ModelRates = { inputPerMillion: 3, outputPerMillion: 15 };

const warnedModels = new Set<string>();

export function ratesForModel(model: string): ModelRates {
  const rate = RATES[model];
  if (rate) return rate;
  if (!warnedModels.has(model)) {
    // eslint-disable-next-line no-console
    console.warn(
      `[cost-rates] Unknown model "${model}" — using fallback rates (Sonnet-equivalent). Add to cost-rates.ts to fix dashboards.`,
    );
    warnedModels.add(model);
  }
  return FALLBACK;
}

/**
 * Compute USD cost from token usage.
 * Returns a number rounded to 6 decimal places (matches the
 * `numeric(10,6)` precision of `agent_chat_transcripts.cost_usd`).
 */
export function computeCostUsd(
  model: string,
  tokensIn: number,
  tokensOut: number,
): number {
  const r = ratesForModel(model);
  const cost =
    (tokensIn / 1_000_000) * r.inputPerMillion +
    (tokensOut / 1_000_000) * r.outputPerMillion;
  // Round to 6 decimals to fit the column.
  return Math.round(cost * 1_000_000) / 1_000_000;
}
