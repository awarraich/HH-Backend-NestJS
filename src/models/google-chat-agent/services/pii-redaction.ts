/**
 * Lightweight PII redaction applied to transcript payloads when the
 * GOOGLE_CHAT_AGENT_PII_REDACTION env flag is on. Default is OFF — the plan
 * defers turning it on until compliance gate C8 is cleared (see plan §0).
 *
 * Scope intentionally narrow:
 *   - email addresses → `[redacted-email]`
 *   - phone numbers (loose match, 7+ digits with separators) → `[redacted-phone]`
 *
 * Anything trickier (employee names, medical context in free text) is out
 * of scope for v1 and would require a real classifier. Strings are scanned
 * recursively through arrays and plain objects.
 */

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
// Matches sequences with 7+ digits broken by spaces, dashes, dots, or parens.
// Conservative — won't catch e.g. "123-456" but also won't flag dates.
const PHONE_RE = /(?:\+?\d[\d\s\-().]{6,}\d)/g;

export function redactString(input: string): string {
  return input
    .replace(EMAIL_RE, '[redacted-email]')
    .replace(PHONE_RE, (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 7 ? '[redacted-phone]' : m;
    });
}

export function redactPayload(value: unknown): unknown {
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(redactPayload);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactPayload(v);
    }
    return out;
  }
  return value;
}
