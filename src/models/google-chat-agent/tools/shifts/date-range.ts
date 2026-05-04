/**
 * Default date range for "what are my shifts?" — today through 7 days out,
 * inclusive. The caller can override `from` / `to` (YYYY-MM-DD strings)
 * via tool input.
 */
export function defaultShiftRange(now: Date = new Date()): {
  from: string;
  to: string;
} {
  const start = new Date(now);
  start.setUTCHours(0, 0, 0, 0);
  const end = new Date(start);
  end.setUTCDate(end.getUTCDate() + 7);
  return {
    from: toDateOnly(start),
    to: toDateOnly(end),
  };
}

export function toDateOnly(d: Date): string {
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function resolveRange(input: {
  from?: string;
  to?: string;
}): { from: string; to: string } {
  const def = defaultShiftRange();
  return {
    from: input.from ?? def.from,
    to: input.to ?? def.to,
  };
}
