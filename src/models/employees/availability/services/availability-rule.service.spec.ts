import { toDateColumnValue } from './availability-rule.service';

/**
 * REGRESSION (real Chat dev test):
 *   User asked "until June 5" → DB stored 2026-06-04. Cause: `new Date('2026-06-05')`
 *   is UTC midnight; TypeORM serializes Date → PG `date` columns via local-time
 *   components, so the Date projected to the previous day in tz west of UTC.
 *
 * Fix: bypass Date construction entirely. TypeORM's `mixedDateToDateString`
 * passes string values straight through to PG, which stores them in the
 * `date` column without any timezone interpretation. These tests pin that
 * behavior so the helper can never silently regress to constructing Dates.
 */
describe('toDateColumnValue (tz-drift regression)', () => {
  it('returns the YYYY-MM-DD string verbatim (NOT a Date object)', () => {
    const v = toDateColumnValue('2026-06-05');
    // Despite the TS return type of Date, the runtime value is a string —
    // that's the whole point: TypeORM passes strings to PG date columns
    // without timezone-coercing them through Date local-component extraction.
    expect(typeof v).toBe('string');
    expect(v).toBe('2026-06-05' as unknown as Date);
  });

  it('does not construct a Date — guards against accidental refactors', () => {
    // If someone "tidies" the helper to `new Date(yyyyMmDd)` thinking it
    // looks cleaner, this test fails immediately. The whole bug class
    // returns the moment a Date object is involved.
    const v = toDateColumnValue('2026-06-05') as unknown;
    expect(v instanceof Date).toBe(false);
  });

  it('matches across boundary timezones — input string is identity', () => {
    // The previous "UTC noon" approach broke at UTC+12. Pass-through has
    // no concept of timezone at all — the string is what gets to PG.
    const dates = ['2026-01-01', '2026-06-05', '2026-12-31', '2099-02-28'];
    for (const d of dates) {
      expect(toDateColumnValue(d)).toBe(d as unknown as Date);
    }
  });
});
