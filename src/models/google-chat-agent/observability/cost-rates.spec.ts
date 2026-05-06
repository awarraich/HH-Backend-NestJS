import { computeCostUsd, ratesForModel } from './cost-rates';

describe('cost-rates (M16)', () => {
  it('returns the right rates for known models', () => {
    expect(ratesForModel('gpt-4o')).toEqual({
      inputPerMillion: 2.5,
      outputPerMillion: 10,
    });
    expect(ratesForModel('gpt-4o-mini')).toEqual({
      inputPerMillion: 0.15,
      outputPerMillion: 0.6,
    });
    expect(ratesForModel('claude-sonnet-4-5-20250929')).toEqual({
      inputPerMillion: 3,
      outputPerMillion: 15,
    });
    expect(ratesForModel('claude-haiku-4-5-20251001')).toEqual({
      inputPerMillion: 1,
      outputPerMillion: 5,
    });
  });

  it('falls back gracefully on an unknown model', () => {
    const rates = ratesForModel('made-up-model-x');
    expect(rates.inputPerMillion).toBeGreaterThan(0);
    expect(rates.outputPerMillion).toBeGreaterThan(0);
  });

  it('computes USD cost correctly for a typical gpt-4o turn', () => {
    // 1000 input + 500 output @ gpt-4o rates:
    // 1000 / 1M * 2.5 = 0.0025
    // 500 / 1M * 10 = 0.005
    // total = 0.0075
    expect(computeCostUsd('gpt-4o', 1000, 500)).toBeCloseTo(0.0075, 6);
  });

  it('computes USD cost correctly for gpt-4o-mini', () => {
    // 5000 input + 200 output @ mini rates:
    // 5000 / 1M * 0.15 = 0.00075
    // 200 / 1M * 0.6 = 0.00012
    // total = 0.00087
    expect(computeCostUsd('gpt-4o-mini', 5000, 200)).toBeCloseTo(0.00087, 6);
  });

  it('rounds to 6 decimal places to match the cost_usd column precision', () => {
    // Force a value that would have more than 6 decimals if not rounded.
    const cost = computeCostUsd('gpt-4o', 1, 1);
    const decimals = (cost.toString().split('.')[1] ?? '').length;
    expect(decimals).toBeLessThanOrEqual(6);
  });

  it('returns 0 for zero tokens', () => {
    expect(computeCostUsd('gpt-4o', 0, 0)).toBe(0);
  });
});
