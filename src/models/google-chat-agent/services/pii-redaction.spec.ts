import { redactPayload, redactString } from './pii-redaction';

describe('redactString', () => {
  it('replaces email addresses with [redacted-email]', () => {
    expect(redactString('Contact me at sara@example.com please')).toBe(
      'Contact me at [redacted-email] please',
    );
  });

  it('replaces multiple emails in the same string', () => {
    expect(
      redactString('a@b.com and c@d.org are both here'),
    ).toBe('[redacted-email] and [redacted-email] are both here');
  });

  it('replaces phone numbers with 7+ digits', () => {
    expect(redactString('Call me at 555-867-5309 today')).toContain(
      '[redacted-phone]',
    );
  });

  it('does NOT replace short digit sequences (false-positive guard)', () => {
    expect(redactString('Room 123')).toBe('Room 123');
  });

  it('leaves clean text unchanged', () => {
    expect(redactString('What are my shifts this week?')).toBe(
      'What are my shifts this week?',
    );
  });
});

describe('redactPayload', () => {
  it('redacts strings nested in objects', () => {
    expect(
      redactPayload({
        text: 'Contact sara@example.com',
        nested: { phone: 'Call 555-867-5309' },
      }),
    ).toEqual({
      text: 'Contact [redacted-email]',
      nested: { phone: 'Call [redacted-phone]' },
    });
  });

  it('redacts strings nested in arrays', () => {
    expect(redactPayload(['a@b.com', { x: 'c@d.com' }])).toEqual([
      '[redacted-email]',
      { x: '[redacted-email]' },
    ]);
  });

  it('passes through non-string primitives unchanged', () => {
    expect(redactPayload(42)).toBe(42);
    expect(redactPayload(true)).toBe(true);
    expect(redactPayload(null)).toBe(null);
    expect(redactPayload(undefined)).toBe(undefined);
  });
});
