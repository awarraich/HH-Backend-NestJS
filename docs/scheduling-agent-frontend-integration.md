# Scheduling Agent — Frontend Integration Guide

This document lists **everything the frontend must do** to make the scheduling
assistant reliable across multi-turn conversations (e.g. discovery → "Yes" →
assignment). Missing any of these will cause the agent to lose UUIDs across
turns and fabricate fake ones, which surfaces as repeated "Assignment failed"
cards.

Endpoint: `POST /v1/api/scheduling-agent`
Auth: JWT bearer + org role guard (`OWNER`, `HR`, `MANAGER`).

---

## 1. Request / response contract

### Request body

| Field            | Type                                               | Required | Notes                                                                    |
| ---------------- | -------------------------------------------------- | -------- | ------------------------------------------------------------------------ |
| `query`          | `string` (≤ 2000 chars)                            | yes      | The user's current message.                                              |
| `organizationId` | `string` (UUID)                                    | yes      | Org the user is working in.                                              |
| `timezone`       | `string` (IANA, ≤ 100 chars)                       | no       | e.g. `"America/Los_Angeles"`. Defaults to US Pacific if omitted.         |
| `context`        | `object`                                           | no       | Free-form page context — see §4.                                         |
| `history`        | `Array<{role: 'user' \| 'assistant', content}>`    | no       | Prior turns, oldest first, **up to 40 entries** (server caps).           |
| `priorToolCalls` | `Array<{name, arguments, result}>`                 | no       | Tool trace from the **immediately prior** response, **up to 24 entries**.|

### Response body

```json
{
  "success": true,
  "data": {
    "answer": "string — may contain <!-- ASSIGNMENTS: [...] --> HTML comments",
    "toolCalls": [
      { "name": "list_shifts", "arguments": { /* ... */ }, "result": { /* ... */ } },
      /* ... */
    ]
  }
}
```

You need **both** `answer` and `toolCalls` from every response. Store them.

---

## 2. Session state (store exactly these two things)

```ts
type ChatSession = {
  // Every user and assistant turn, oldest first. Assistant messages must be
  // stored VERBATIM, including any <!-- ASSIGNMENTS: ... --> HTML comments.
  history: Array<{ role: 'user' | 'assistant'; content: string }>;

  // The toolCalls from ONLY the most recent assistant response. Replace
  // (do not append) this on every turn.
  lastToolCalls: Array<{ name: string; arguments: unknown; result: unknown }>;
};
```

### Why these two

- **`history`** gives the LLM multi-turn memory. Back-references like "this
  shift" or "that employee" only work if the prior assistant text is replayed.
- **`lastToolCalls`** is the UUID-rescue channel. The server flattens it into
  a synthetic system message so the LLM can see real UUIDs from the previous
  turn's tool results — even if the model forgot to embed them in an
  `<!-- ASSIGNMENTS: ... -->` block. Without this, the "Yes" turn has nothing
  real to work with and the model will fabricate UUIDs that don't exist.

---

## 3. Send pattern

```ts
async function sendMessage(userText: string, session: ChatSession) {
  const res = await fetch('/v1/api/scheduling-agent', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify({
      query: userText,
      organizationId,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      context: buildPageContext(),                        // see §4
      history: session.history.slice(-20),                // last 20 turns
      priorToolCalls: session.lastToolCalls.slice(-12),   // last 12 calls
    }),
  });

  const { data } = await res.json();

  // 1. Append the user turn and the NEW assistant turn to history.
  //    Store assistant content VERBATIM — do NOT strip HTML comments here.
  session.history.push({ role: 'user', content: userText });
  session.history.push({ role: 'assistant', content: data.answer });

  // 2. REPLACE lastToolCalls with this response's toolCalls. Do not accumulate.
  session.lastToolCalls = data.toolCalls ?? [];

  return data;
}
```

### Server-side caps (enforce client-side too)

- `history` — **40 max**, cap at 20 for headroom.
- `priorToolCalls` — **24 max**, cap at 12.
- `query` — **2000 chars max**.
- Per history message `content` — **8000 chars max**.

---

## 4. Page context

Whatever the user is looking at on the page. The agent uses these as
defaults when the user's message omits a specific entity.

```ts
type Context = {
  viewing?: string;          // free-form label, e.g. "employee-schedule-grid"
  date?: string;             // YYYY-MM-DD
  shiftId?: string;          // UUID — preferred over name
  shiftName?: string;        // fallback when no id
  departmentId?: string;
  departmentName?: string;
  stationId?: string;
  stationName?: string;
  // arbitrary extra keys accepted
};
```

Pass the **UUID** whenever you have it — the agent will skip `search_shifts`
and jump straight to the work.

---

## 5. Rendering rules

### Keep HTML comments out of the UI but IN state

The assistant's `answer` will sometimes contain:

```html
<!-- ASSIGNMENTS: [{"shift_id":"...","employee_id":"...","scheduled_date":"2026-04-18"}] -->
```

These must survive to the next turn (they live in `session.history`). But
they must NOT render visibly.

Two clean options:

**(a) Use a markdown renderer that drops comments by default.**
`react-markdown`, `marked`, and most others drop HTML comments out of the box.
Verify with a test string.

**(b) Split display value from stored value:**

```ts
const displayable = data.answer.replace(/<!--[\s\S]*?-->/g, '');
// Render `displayable`, but STORE `data.answer` in history.
```

Do **not** write the stripped version back into `session.history`.

### Don't echo raw UUIDs anywhere

The agent is explicitly prompted never to put UUIDs in visible text. If one
leaks through, treat it as a bug — don't build UI that depends on it.

---

## 6. Success / failure cards from `toolCalls`

The server returns every tool call the agent made this turn. Use that trace
to drive side-panel cards (assignment success, shift list, availability list,
etc.).

```ts
for (const call of data.toolCalls) {
  switch (call.name) {
    case 'assign_employee_to_shift': {
      const r = call.result as { success: boolean; error?: string; employee_name?: string; employee_shift?: unknown };
      if (r.success) {
        renderAssignmentSuccess(r);
      } else {
        // error is human-readable now, e.g.
        // "employee_id xxx does not exist in this organization. Do NOT retry..."
        renderAssignmentFailure(r.error ?? 'Unknown error');
      }
      break;
    }
    case 'list_shifts':
    case 'search_shifts':
      renderShiftList((call.result as any).shifts);
      break;
    case 'get_employee_availability':
    case 'search_available_employees':
      renderAvailabilityList(
        (call.result as any).availability ?? (call.result as any).candidates
      );
      break;
    // ...
  }
}
```

---

## 7. Validation checklist (use this to debug)

Open DevTools → Network → watch the POST body on the **"Yes"** turn (the one
that actually assigns).

- [ ] `history` is non-empty and **includes the prior assistant turn** with
      any `<!-- ASSIGNMENTS: ... -->` block **still inside** `content`.
- [ ] `priorToolCalls` is non-empty and contains the prior turn's
      `list_shifts` / `get_employee_availability` / `search_available_employees`
      results.
- [ ] `timezone` is set (e.g. `"America/Los_Angeles"`), not `undefined`.
- [ ] `organizationId` is the active org's UUID.

If **any** of these are missing on the "Yes" turn, the backend cannot help —
fix the frontend first.

Rough smoke test:
1. Send "What shifts are available today?"
2. In the response, confirm `toolCalls` contains at least one entry.
3. Send "Yes" and confirm the request body has `priorToolCalls` populated
   with those same entries.

---

## 8. Edge cases & gotchas

- **Page refresh / new tab** — if `session` only lives in component state,
  the next message starts with empty `history` and `priorToolCalls`. Persist
  to `sessionStorage` or a backend session if you want the conversation to
  survive reloads.
- **User edits a prior message** — re-trim `history` to that point before
  sending. Don't send stale assistant turns that no longer reflect the flow.
- **"New chat" button** — clear both `history` AND `lastToolCalls`.
- **Error responses (4xx/5xx)** — do NOT push the assistant placeholder into
  `history`. Retry with the same state.
- **Long tool results** — the server truncates each replayed tool result to
  2000 chars in the prompt. You can still display the full result client-side
  from `toolCalls`; the truncation only affects what the LLM sees.

---

## 9. TypeScript types (copy/paste into your shared types module)

```ts
export type SchedulingAgentRole = 'user' | 'assistant';

export interface SchedulingAgentHistoryMessage {
  role: SchedulingAgentRole;
  content: string;
}

export interface SchedulingAgentToolCall {
  name: string;
  arguments: unknown;
  result: unknown;
}

export interface SchedulingAgentContext {
  viewing?: string;
  date?: string;
  shiftId?: string;
  shiftName?: string;
  departmentId?: string;
  departmentName?: string;
  stationId?: string;
  stationName?: string;
  [key: string]: string | undefined;
}

export interface SchedulingAgentRequest {
  query: string;
  organizationId: string;
  timezone?: string;
  context?: SchedulingAgentContext;
  history?: SchedulingAgentHistoryMessage[];
  priorToolCalls?: SchedulingAgentToolCall[];
}

export interface SchedulingAgentResponse {
  answer: string;
  toolCalls: SchedulingAgentToolCall[];
}
```

---

## TL;DR

1. Keep `history` + `lastToolCalls` in session state.
2. On every request, send `history` (last 20) and `priorToolCalls` (last 12).
3. Store assistant `answer` **verbatim** — never strip HTML comments before
   saving to history.
4. Drop HTML comments **at render time only**.
5. Always send `timezone`.
6. On "New chat", clear both buffers.
