# Google Chat Scheduling Agent — Plan

A conversational AI agent that lives inside the existing HomeHealth Reminders Google Chat bot. Employees and managers DM the bot to read and write **scheduling** data — listing shifts, viewing/setting availability, requesting time off, and (for managers) assigning shifts based on who's available.

This document is **plan-only**. It is paired with — but separate from — the notification integration tracked in [integration-google-chat-plan.md](integration-google-chat-plan.md). It does not implement anything yet; it is the spec to work against when implementation starts.

> **Scope discipline.** Read/write surface is restricted to scheduling and availability (the entities under [`src/models/organizations/scheduling/`](../../../src/models/organizations/scheduling/) and [`src/models/employees/availability/`](../../../src/models/employees/availability/)). HR documents, training, payroll, patients, etc. are explicitly **out of scope** for this initiative — they may follow as separate agent surfaces later.

---

## 1. Architecture summary

```
Google Chat (DM)
   │
   ▼
POST /v1/api/google-chat/webhook   (existing, module 3 of notif plan)
   │
   ├── ADDED_TO_SPACE / REMOVED_FROM_SPACE  → existing handlers (untouched)
   │
   └── MESSAGE                              → SchedulingAgentService.handle()
                                                │
                                                ▼
                                          1. Resolve identity (chat_user_id → HH user)
                                          2. Load thread state (Redis)
                                          3. Append user turn → call Claude with tools
                                          4. Tool-use loop:
                                               ├─ getMyShifts / setAvailabilityRule / …
                                               │     → call existing NestJS services
                                               │     → enforce RBAC of resolved user
                                               └─ return tool result to model
                                          5. Render final assistant turn
                                               ├─ structured Card v2 (for lists/tables)
                                               └─ plain text (for prose / errors)
                                          6. POST reply to Chat thread
                                          7. Log transcript row
```

**Key choice:** Option A from the discussion — LLM lives inside NestJS, tools are thin wrappers over existing services. No external MCP server in v1. The tool registry is structured so Option B (expose the same tools as a standalone MCP server) is a future refactor, not a rewrite (see F-items at the bottom).

**Model routing:**
- Sonnet 4.6 for the tool-use loop (default).
- Haiku 4.5 as a fallback for trivial classification turns (greetings, "thanks", help) — controlled by a cheap pre-router.
- Prompt caching enabled on the system prompt + tool definitions (they barely change between turns).

---

## 2. Module map

| # | Module | One-line scope |
|---|---|---|
| A1 | Foundation — Anthropic SDK + config | `@anthropic-ai/sdk` install, env vars, `ClaudeClient` provider |
| A2 | Identity resolver | Chat user → HH user with org + roles loaded |
| A3 | Conversation state | Thread-keyed turn history in Redis with TTL |
| A4 | Tool registry & contracts | Zod-typed tool defs → Claude JSON schemas; central registry |
| A5 | Read tools — shifts | `listMyShifts`, `getShiftDetails`, `listShiftsByDate`, `listOpenShifts` |
| A6 | Read tools — availability | `getMyAvailability`, `getMyTimeOffRequests`, `getEmployeeAvailability` |
| A7 | Read tools — assignment helpers | `listAssignmentsForShift`, `findAvailableEmployeesForShift` |
| A8 | Write tools — availability (employee self) | `setAvailabilityRule`, `requestTimeOff`, `cancelTimeOffRequest` |
| A9 | Write tools — shift assignment (manager) | `assignShift`, `unassignShift`, `swapShift` |
| A10 | Webhook MESSAGE branch | Route MESSAGE events into the agent pipeline |
| A11 | Response rendering | Card v2 builder for shifts/availability lists; plain text fallback |
| A12 | RBAC enforcement | One choke point all tools pass through; deny-by-default |
| A13 | Transcript & audit logging | `agent_chat_transcripts` table; tool calls + redactions |
| A14 | Rate limiting & abuse controls | Per-user, per-org token + request budgets |
| A15 | Model router | Haiku-first triage → Sonnet on tool use |
| A16 | Observability | Structured logs, Sentry, latency/cost metrics |
| A17 | Feature flag & rollout | Per-org enable; allowlist; kill switch |
| A18 | Help & discoverability | `/help` slash command + onboarding card |

Status legend matches the notification plan: ✅ done · 🚧 in progress · ❌ not started · 💤 deferred.

All modules below currently: **❌ Not started.**

---

## 3. Modules in detail

Each module section follows the same shape:
- **Goal** — what it does and why
- **Touch points** — files/services it creates or modifies
- **Contract** — public surface (types, env vars, table columns, etc.)
- **Tests** — unit + integration; what each test proves
- **Done when** — verification gate before flipping to ✅

---

### A1. Foundation — Anthropic SDK + config ❌

**Goal.** Get a typed, DI-injectable Claude client into the Nest container and configured for prompt caching.

**Touch points:**
- `package.json`: add `@anthropic-ai/sdk`.
- `src/config/scheduling-agent/`: new config namespace (`SCHEDULING_AGENT_*` env vars).
- `src/models/scheduling-agent/` (new module): `claude.client.ts`, `scheduling-agent.module.ts`.

**Contract:**
```
SCHEDULING_AGENT_ENABLED=true|false      # global kill switch
ANTHROPIC_API_KEY=sk-ant-...
SCHEDULING_AGENT_MODEL=claude-sonnet-4-6
SCHEDULING_AGENT_TRIAGE_MODEL=claude-haiku-4-5-20251001
SCHEDULING_AGENT_MAX_TOKENS=2048
SCHEDULING_AGENT_TURN_TIMEOUT_MS=30000
```

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A1-U1 | unit | `ClaudeClient` is constructed with the API key from config; throws on missing key when `ENABLED=true` |
| A1-U2 | unit | Disabled flag (`SCHEDULING_AGENT_ENABLED=false`) makes the provider a no-op stub instead of failing at boot |
| A1-I1 | integration | Tiny live call to `claude-haiku-4-5-20251001` returns a non-empty completion (skipped in CI without API key, gated by `RUN_LIVE_AI_TESTS=1`) |

**Done when:** boot succeeds with flag on and off; live integration test produces a completion locally.

---

### A2. Identity resolver ❌

**Goal.** Given a Google Chat `user.name` (e.g. `users/123…`), return the HH `User` with `organization_id` and roles loaded — or `null` if unlinked. This is the *only* trusted source of "who is asking?" — every tool reads from this.

**Touch points:**
- `src/models/scheduling-agent/services/agent-identity.service.ts`.
- Reuses `user_chat_connections` from notif module 5 — does **not** introduce a parallel mapping table.

**Contract:**
```ts
interface ResolvedAgentUser {
  userId: number;
  organizationId: number;
  roles: string[];          // e.g. ['employee', 'manager']
  timezone: string;
  chatUserId: string;
  chatSpaceName: string;
}
async resolve(chatUserId: string): Promise<ResolvedAgentUser | null>;
```

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A2-U1 | unit | Returns null when no `user_chat_connections` row exists |
| A2-U2 | unit | Returns null when row exists but `status='revoked'` |
| A2-U3 | unit | Loads roles from join; preserves multi-role |
| A2-U4 | unit | Returns user's org timezone, not server tz |
| A2-I1 | integration | Real DB seed: linked employee resolves; revoked user does not; unlinked does not |

**Done when:** all five tests green; manually DM-tested with a linked + an unlinked test account.

---

### A3. Conversation state ❌

**Goal.** Persist last N turns per Chat thread so follow-ups ("and the week after?") have context. Short TTL — this is not durable history.

**Touch points:**
- `src/models/scheduling-agent/services/conversation-state.service.ts` — Redis-backed, key `agent:thread:<thread.name>`.
- Reuses existing Redis (BullMQ already wired in notif module 12).

**Contract:**
```ts
interface AgentTurn {
  role: 'user' | 'assistant' | 'tool';
  content: unknown;       // shaped per Anthropic SDK Message format
  ts: string;             // ISO
}
get(threadKey): Promise<AgentTurn[]>;       // up to MAX_TURNS (default 12)
append(threadKey, turn): Promise<void>;
clear(threadKey): Promise<void>;            // for /reset slash command
// TTL: 30 minutes since last turn
```

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A3-U1 | unit | `append` rolls window when length > MAX_TURNS (oldest dropped) |
| A3-U2 | unit | `clear` removes the key |
| A3-U3 | unit | TTL is reset on every `append` |
| A3-I1 | integration | Two sequential calls in the same thread share state; different threads do not |
| A3-I2 | integration | Key expires after TTL (use `redis.pttl` to assert) |

**Done when:** integration test demonstrates a multi-turn exchange survives across two webhook calls within TTL and is gone after.

---

### A4. Tool registry & contracts ❌

**Goal.** A single typed registry so that adding a tool is one file, and every tool is automatically: (a) exposed to Claude with a JSON schema, (b) gated through RBAC (A12), and (c) logged in the transcript (A13).

**Touch points:**
- `src/models/scheduling-agent/tools/tool.types.ts` — generic `Tool<TInput, TOutput>` interface.
- `src/models/scheduling-agent/tools/tool.registry.ts` — registers tools, builds Anthropic `tools` payload with cache-control, dispatches by name.
- Uses `zod` (already in repo) → JSON Schema via `zod-to-json-schema`.

**Contract:**
```ts
interface Tool<I, O> {
  name: string;                              // 'listMyShifts'
  description: string;                       // shown to the model
  input: z.ZodType<I>;
  output: z.ZodType<O>;
  requiredRoles?: string[];                  // for RBAC layer
  handler(input: I, ctx: AgentContext): Promise<O>;
}
```

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A4-U1 | unit | Registry rejects two tools with the same name |
| A4-U2 | unit | `getAnthropicToolsPayload()` produces JSON Schema with `additionalProperties: false` and matches Zod shape |
| A4-U3 | unit | `dispatch('unknownTool', …)` throws a structured `ToolNotFoundError` |
| A4-U4 | unit | Tool whose `requiredRoles` aren't satisfied is omitted from the per-user tools payload |
| A4-U5 | unit | Output that fails the Zod schema raises before being returned to the model (catches buggy tools) |

**Done when:** all unit tests green; smoke registration of a no-op `ping` tool returns "pong" through the registry.

---

### A5. Read tools — shifts ❌

**Goal.** First useful surface. Read-only, employee-self-scoped except where noted.

**Tools:**
| Tool | Description | Roles |
|---|---|---|
| `listMyShifts` | shifts assigned to the caller, optional date range, default = next 7 days | employee |
| `getShiftDetails` | full details of one shift the caller is assigned to (or any if manager) | employee/manager |
| `listShiftsByDate` | all shifts in caller's org for a date / range | manager |
| `listOpenShifts` | unassigned shifts in caller's org | manager |

**Touch points:**
- `src/models/scheduling-agent/tools/shifts/*.tool.ts` — one file per tool.
- Wraps `EmployeeShiftService` and `ShiftService` from `src/models/organizations/scheduling/services/`. **No** new query logic — if a shape is missing, extend the underlying service first.

**Tests (per tool):**

| ID | Type | Proves |
|---|---|---|
| A5-U1 | unit | `listMyShifts` filters to caller's `employee_id` only; never returns another employee's shift even if service is mocked to return more |
| A5-U2 | unit | `listMyShifts` defaults to today→+7d when no range given |
| A5-U3 | unit | `getShiftDetails` denies a non-manager asking for someone else's shift |
| A5-U4 | unit | `listShiftsByDate` denies an `employee` role |
| A5-U5 | unit | `listOpenShifts` returns only shifts in caller's `organization_id` |
| A5-I1 | integration | Seed two orgs; manager in org A cannot see org B's open shifts |
| A5-I2 | integration | Date-range filtering behaves the same as the underlying `EmployeeShiftService` direct call |

**Done when:** integration tests pass; manual DM "what are my shifts this week?" returns the correct set in the test org.

---

### A6. Read tools — availability ❌

**Goal.** Caller-self by default; managers can query an employee by id/name.

**Tools:**
| Tool | Description | Roles |
|---|---|---|
| `getMyAvailability` | active availability rules + work prefs for the caller | employee |
| `getMyTimeOffRequests` | pending + approved + denied; default last 30 / next 60 days | employee |
| `getEmployeeAvailability` | as above, by employee id, in same org | manager |

**Touch points:**
- `src/models/scheduling-agent/tools/availability/*.tool.ts`.
- Wraps `AvailabilityRuleService`, `TimeOffRequestService`, `WorkPreferenceService`, `EmployeeAvailabilityService`.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A6-U1 | unit | `getMyAvailability` returns active rules only (not soft-deleted/expired) |
| A6-U2 | unit | `getEmployeeAvailability` cross-org returns 403-equivalent error |
| A6-U3 | unit | Time-off statuses are normalized to `pending|approved|denied|cancelled` regardless of underlying enum drift |
| A6-I1 | integration | Manager in org A querying employee in org A succeeds; org B fails |

**Done when:** unit + cross-org integration test green.

---

### A7. Read tools — assignment helpers ❌

**Goal.** The "who could fill this shift?" question — where the agent earns its keep.

**Tools:**
| Tool | Description | Roles |
|---|---|---|
| `listAssignmentsForShift` | who is currently assigned (with role) | manager |
| `findAvailableEmployeesForShift` | candidates ranked by: matches role required, available per `availability_rules`, no overlapping `employee_shift`, no approved `time_off_request`, work-preference fit | manager |

**Touch points:**
- `src/models/scheduling-agent/tools/assignment/*.tool.ts`.
- The `findAvailableEmployeesForShift` tool composes `EmployeeAvailabilityService` + `EmployeeShiftService` + `TimeOffRequestService`. Logic lives in a new `ShiftMatcherService` co-located in the agent module — *not* in the scheduling module — because it's the agent's domain composition, not a generally-useful org-wide query (we'll move it if other callers need it).

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A7-U1 | unit | Excludes employees with overlapping accepted shift |
| A7-U2 | unit | Excludes employees with approved time-off covering the shift window |
| A7-U3 | unit | Excludes employees whose availability rules don't cover the shift window |
| A7-U4 | unit | Includes only employees with the shift's `shift_role` (or unrestricted role match) |
| A7-U5 | unit | Ranks correctly: hard-disqualified always last; tied candidates ordered by recency of last shift (least recent first, to spread load) |
| A7-I1 | integration | Seed 5 employees with realistic availability/time-off; assert candidate list matches the hand-calculated answer |
| A7-I2 | integration | Cross-org isolation as in A5/A6 |

**Done when:** integration test fixture proves the matcher's output equals the documented expected set.

---

### A8. Write tools — availability (employee self) ❌

**Goal.** Employees mutate their own availability through the bot. No admin reach.

**Tools:**
| Tool | Description | Roles |
|---|---|---|
| `setAvailabilityRule` | create/replace a recurring rule (day-of-week + time window) | employee |
| `requestTimeOff` | create a pending time-off request | employee |
| `cancelTimeOffRequest` | cancel one of caller's own pending requests | employee |

**Touch points:**
- `src/models/scheduling-agent/tools/availability-write/*.tool.ts`.
- Wraps `AvailabilityRuleService`, `TimeOffRequestService`. **Does not bypass** existing service-level validation (overlap, min-notice, etc.).

**Confirmation pattern.** Writes always echo back what was changed and offer an undo for 60s within the same thread (UX detail for A11; the tool itself just performs the mutation idempotently when `idempotency_key` is supplied).

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A8-U1 | unit | `setAvailabilityRule` upserts on `(employee_id, day_of_week)` — running twice produces one row, not two |
| A8-U2 | unit | `requestTimeOff` rejects backdated requests (delegates to service validator; tool surfaces the error message) |
| A8-U3 | unit | `cancelTimeOffRequest` denies cancelling someone else's request |
| A8-U4 | unit | `cancelTimeOffRequest` denies cancelling an `approved` request (only `pending` is cancellable) |
| A8-I1 | integration | Round-trip: setAvailabilityRule → getMyAvailability reflects the new rule |
| A8-I2 | integration | Idempotency key prevents duplicate time-off requests on retry |

**Done when:** all tests green; manual DM "I can't work next Tuesday" creates a pending TOR visible in the web UI.

---

### A9. Write tools — shift assignment (manager) ❌

**Goal.** The big one. Manager DMs "assign Sara to the Tuesday 8am shift" and it lands.

**Tools:**
| Tool | Description | Roles |
|---|---|---|
| `assignShift` | assign an employee to a shift (rejects if conflict) | manager |
| `unassignShift` | remove an assignment | manager |
| `swapShift` | atomic unassign A + assign B | manager |

**Hard rules enforced before mutation:**
1. Employee belongs to caller's org.
2. Shift belongs to caller's org.
3. Employee has matching role (or shift role is null).
4. No overlapping accepted shift for the employee.
5. No approved time-off in the shift window.
6. Employee's availability rules cover the shift window — **soft warning, not block**, with a confirmation token returned to the model so it must explicitly re-call with `acknowledge_availability_warning: true`.

**Touch points:**
- `src/models/scheduling-agent/tools/assignment-write/*.tool.ts`.
- A new `ShiftAssignmentService` *may* be needed if existing `EmployeeShiftService` doesn't expose a transactional assign/unassign with the conflict checks above — to be confirmed during A9 spike. If it doesn't, build it in `organizations/scheduling/services/` (not in the agent module) so the web UI can use the same path.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A9-U1 | unit | Rejects assignment when employee has overlapping shift |
| A9-U2 | unit | Rejects assignment when employee has approved TOR |
| A9-U3 | unit | Rejects when role mismatch and shift requires a role |
| A9-U4 | unit | Returns warning (not error) when availability rules don't cover; second call with `acknowledge_availability_warning` succeeds |
| A9-U5 | unit | `swapShift` is atomic — failure to assign B rolls back unassign of A |
| A9-U6 | unit | Cross-org assignment denied |
| A9-I1 | integration | Real DB transaction: concurrent assign of two employees to same single-slot shift — exactly one wins (DB constraint or service-level lock asserted) |
| A9-I2 | integration | After successful assignment, `listAssignmentsForShift` reflects it |

**Done when:** A9-I1 passes (concurrency); manual DM end-to-end assigns and shows in web UI.

---

### A10. Webhook MESSAGE branch ❌

**Goal.** Wire MESSAGE events into the agent without breaking ADDED/REMOVED handlers from the notification flow.

**Touch points:**
- `src/models/notifications/google-chat/webhook.controller.ts` — extend the `MESSAGE` case to call `SchedulingAgentService.handle(event)`.
- The agent service short-circuits if `SCHEDULING_AGENT_ENABLED=false` or the org's feature flag (A17) is off, replying with a "this feature isn't enabled for your org" card.

**Behaviors:**
- Slash commands (Chat-native): `/help`, `/reset`, `/whoami`. Slash commands bypass the LLM and run hard-coded handlers.
- Plain DM text: routed to A15 (model router) → agent loop.
- Empty / attachment-only message: friendly "I don't read attachments yet" reply.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A10-U1 | unit | ADDED_TO_SPACE still routes to the existing handler (regression) |
| A10-U2 | unit | MESSAGE with no text and no slash command produces the attachment-only reply |
| A10-U3 | unit | `/reset` clears the thread state (calls A3.clear) |
| A10-U4 | unit | Disabled flag returns the disabled-card without invoking Claude |
| A10-I1 | integration | Real webhook payload (captured fixture) → agent reply JSON validated against Chat's response schema |

**Done when:** notification module's existing tests still pass; agent integration test passes with a captured Chat MESSAGE payload.

---

### A11. Response rendering ❌

**Goal.** Don't dump prose paragraphs into Chat. Render structured tool results as Card v2; only fall back to text for greetings, errors, and short answers.

**Touch points:**
- `src/models/scheduling-agent/rendering/`:
  - `shift-list.card.ts`, `shift-detail.card.ts`, `availability.card.ts`, `time-off.card.ts`, `assignment-result.card.ts`.
- Each card builder is a pure function `(toolName, toolOutput) → CardV2`.

**Rule:** the model never emits cards directly. The agent loop inspects the *last tool result*; if there's a registered renderer for it, the assistant's text becomes the card's "summary" header, and the structured data renders as the card body. If there's no renderer, plain text only.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A11-U1 | unit | Empty list renders the "nothing scheduled" card variant |
| A11-U2 | unit | More than `MAX_INLINE_ROWS` results render with a "view all in app" deep link instead of pagination |
| A11-U3 | unit | Card payload size stays under Google's 32KB limit for a stress fixture (50 shifts) |
| A11-U4 | unit | Tool errors render an error card with the `errorId` so support can grep logs |
| A11-I1 | integration | Render-then-post round trip: card payload accepted by Chat API in the staging space |

**Done when:** A11-I1 produces a valid card in the dev test space.

---

### A12. RBAC enforcement ❌

**Goal.** A single function every tool dispatch passes through. Deny by default. Tool's `requiredRoles` is necessary but not sufficient — the tool's *handler* must also receive the resolved user and pass it to the underlying service so service-level checks fire too.

**Touch points:**
- `src/models/scheduling-agent/rbac/agent-rbac.guard.ts`.
- Wraps `Registry.dispatch` such that:
  1. Caller has at least one of `requiredRoles`, OR tool has none and caller is at least `employee`.
  2. The underlying service call is made with the resolved user as the `actor`, never with a service-account identity.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A12-U1 | unit | Tool with `requiredRoles=['manager']` denied for an employee |
| A12-U2 | unit | Caller without any HH role (chat-linked but role row missing) denied |
| A12-U3 | unit | Service-level error (e.g. policy denies even a manager) propagates as a structured `RbacDeniedError` rather than a generic 500 |
| A12-U4 | unit | The actor passed to underlying services is the resolved HH user, not the bot's service account (mock asserts `service.foo(...)` called with `{ actorUserId: <resolvedUserId> }`) |

**Done when:** the four unit tests pass; a "negative" manual DM test by an employee asking for a manager-only tool gets denied with a clear message.

---

### A13. Transcript & audit logging ❌

**Goal.** Every agent turn (user message, model output, each tool call + result) goes to a row. Used for debugging, abuse review, and tuning prompts.

**Touch points:**
- New migration `<timestamp>-create-agent-chat-transcripts.ts`:
  ```
  agent_chat_transcripts(
    id bigserial pk,
    organization_id int not null,
    user_id int not null,
    chat_thread_name text not null,
    turn_index int not null,
    role text not null,            -- 'user' | 'assistant' | 'tool'
    tool_name text null,
    payload jsonb not null,        -- full content (with PII redaction policy applied at write)
    tokens_in int null,
    tokens_out int null,
    cost_usd numeric(10,6) null,
    created_at timestamptz default now()
  )
  index on (organization_id, user_id, created_at desc)
  index on (chat_thread_name, turn_index)
  ```
- `agent-transcript.service.ts`.

**Redaction policy (v1):** payload is stored verbatim — but a per-org `PII_REDACTION` flag (default off) can swap in a redactor that replaces email/phone with `[redacted]`. We stay on the defer-side until legal weighs in (notif open-question carryover).

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A13-U1 | unit | One DB row per turn, with monotonic `turn_index` per `chat_thread_name` |
| A13-U2 | unit | Token counts match the Anthropic SDK's reported usage |
| A13-U3 | unit | `PII_REDACTION=on` masks email/phone; off stores raw |
| A13-I1 | integration | Failure to write a transcript does not block the user reply (logged + Sentry'd, not thrown) |

**Done when:** A13-I1 verified by injecting a write failure and confirming the user still got their answer.

---

### A14. Rate limiting & abuse controls ❌

**Goal.** A single chatty user or runaway thread can't burn a month of API budget in a day.

**Limits (v1):**
- Per-user: 60 messages / hour, 200 / day.
- Per-org: 10,000 messages / day.
- Per-thread: 50 turns within TTL window before forced `/reset` prompt.

**Touch points:**
- `src/models/scheduling-agent/limits/rate-limit.service.ts`, Redis-backed sliding window.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A14-U1 | unit | 61st request in an hour is denied with a friendly card |
| A14-U2 | unit | Org-level cap hits before per-user when both apply |
| A14-U3 | unit | Counter resets correctly at window boundary |
| A14-I1 | integration | Concurrent requests counted exactly once (Redis Lua / `INCR` semantics) |

**Done when:** unit tests green; integration test with 100 concurrent fakes shows exactly one over-limit denial at the boundary.

---

### A15. Model router ❌

**Goal.** Don't pay Sonnet prices for "hi" or "thanks." Cheap classification first; escalate to Sonnet when the model wants to call a tool or produce a substantive answer.

**Routing:**
1. Preprocessor: if message matches a small allowlist of trivial intents (greeting, thanks, help → `/help` redirect), reply locally.
2. Else: single Haiku call with a tight system prompt and a "should I escalate?" tool. If Haiku decides yes, hand off to Sonnet with the full tool registry.
3. Else: Haiku's reply is the answer.

**Touch points:**
- `src/models/scheduling-agent/router/model-router.service.ts`.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A15-U1 | unit | "hi" is intercepted before any LLM call (asserts neither client called) |
| A15-U2 | unit | Haiku's escalation tool result triggers Sonnet with the full tools payload |
| A15-U3 | unit | Sonnet timeout surfaces as a "took too long, try again" card, not a 500 |
| A15-I1 | integration | "what are my shifts this week?" → Sonnet tool-use loop end-to-end (live API, gated) |

**Done when:** A15-I1 measurable in dev: greeting cost $0; shift query cost recorded in transcript.

---

### A16. Observability ❌

**Goal.** When something feels off, the on-call engineer can find out why in under 5 minutes.

**What gets emitted:**
- Structured log per turn: `{ turnId, userId, orgId, threadName, model, toolsCalled, tokensIn, tokensOut, costUsd, latencyMs, error? }`.
- Sentry breadcrumb chain per turn; errors tagged with `turnId`.
- Prometheus metrics (or whatever the project uses): `agent_turn_latency_seconds`, `agent_turn_cost_usd`, `agent_tool_calls_total{tool=…}`.

**Touch points:**
- `src/models/scheduling-agent/observability/agent-telemetry.service.ts`.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A16-U1 | unit | A turn that errors emits a log with `error.message` and a Sentry capture (mocked) |
| A16-U2 | unit | Latency metric is recorded even on the error path |
| A16-I1 | integration | Sample turn produces all expected metrics in the test registry |

**Done when:** the metrics are scrapeable in dev and a deliberate error appears in Sentry.

---

### A17. Feature flag & rollout ❌

**Goal.** Per-org enable. Allowlist for early access. Global kill switch.

**Touch points:**
- Reuses `organization_integrations` row from notification module 5; new column `scheduling_agent_enabled boolean default false` (migration in this module).
- Global env: `SCHEDULING_AGENT_ENABLED` from A1 acts as a kill switch — when false, no org's flag matters.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A17-U1 | unit | Org flag false → friendly disabled card without any LLM call |
| A17-U2 | unit | Global kill switch overrides org flag |
| A17-I1 | integration | Toggling the flag mid-session: existing thread stops responding; new threads see the disabled card |

**Done when:** integration test passes; org admin can flip the flag from the existing integrations page (UI work tracked separately if needed).

---

### A18. Help & discoverability ❌

**Goal.** A user who's never used the bot before can find their way in 30 seconds.

**Touch points:**
- `/help` slash command: lists available capabilities by role (so an employee doesn't see manager tools).
- Onboarding card: posted automatically once when the agent flag is first enabled in a thread (one-time per user per org).

**Tests:**

| ID | Type | Proves |
|---|---|---|
| A18-U1 | unit | `/help` content varies by role |
| A18-U2 | unit | Onboarding card posts once per `(user, org)`; second invocation is a no-op |
| A18-I1 | integration | DM `/help` to the bot — card renders with the expected sections |

**Done when:** manual DM test feels usable to someone unfamiliar with the bot.

---

## 4. Dependencies between modules

```
A1 ─┬─► A2 ─┬─► A4 ─┬─► A5 ─┬─► A10 ─► A15 ─► A11
    │       │       │       │
    └─► A3 ─┘       ├─► A6 ─┤
                    │       │
                    ├─► A7 ─┤
                    │       │
                    ├─► A8 ─┤
                    │       │
                    └─► A9 ─┘
                    
A12 ───────► gates dispatch in A4 (registry) — implement alongside A4
A13 ───────► writes from inside A4 dispatch — implement alongside A4
A14 ───────► gates entry to A10 — implement alongside A10
A16 ───────► cross-cuts; instrument as each module lands
A17 ───────► gates A10 — implement alongside A10
A18 ───────► after A10 + A11 are usable
```

**Suggested implementation order (critical path):** A1 → A2 → A3 → A4 (with A12 + A13) → A5 → A11 → A10 (with A14 + A17) → A15 → A6 → A7 → A8 → A9 → A16 → A18.

You can ship a useful read-only v0 after A11. Writes (A8, A9) come last.

---

## 5. Cross-cutting test infrastructure

These are things every module relies on; build them up front during A1.

- **Test harness for tool calls.** A `runTool(toolName, input, asUser)` helper that hits the registry the same way a real Chat MESSAGE would, with full RBAC + transcript + observability — so tests exercise the real pipeline, not the bare handler.
- **DB seed factories** for shifts, employees, availability rules, time-off requests, assignments. Reuse anything that exists; extend per module.
- **Mocked Anthropic client** with deterministic fake completions for unit tests (record-replay style, NOT live).
- **Live integration suite** behind `RUN_LIVE_AI_TESTS=1` for the A1-I1, A15-I1, A11-I1 cases that genuinely need a real Anthropic call.
- **Captured Chat webhook fixtures.** `tests/fixtures/chat-message-*.json` — record real payloads from dev, replay in tests.

---

## 6. Open questions (resolve before starting A8/A9)

1. **Confirmation UX for writes.** Must mutating tools always require an in-thread "yes confirm" turn, or is the model's pre-confirmation prose enough? Default proposal: writes execute immediately, but A11 renders an "undo" card valid for 60s.
2. **PII to Anthropic.** Legal sign-off on sending shift/availability data (employee names, schedules) to Anthropic. Notification module deferred this; it must be answered before A5 ships.
3. **Tool naming surface.** Should tool names match HH internal vocabulary (`employee_shift`) or user-facing vocabulary (`shift`)? Default: user-facing, since the model speaks back to users.
4. **Multi-language.** Arabic queries — at least passive read support. Sonnet handles it natively; renderers (A11) need RTL-safe card structures. Defer past v1 if not urgent.
5. **Audit retention.** How long do we keep `agent_chat_transcripts`? Default proposal: 90 days, then archive to cold storage.

---

## 7. Future enhancements

Stable IDs — never renumber.

- **F1.** Push-style proactive nudges: "you haven't set availability for next month; want me to copy last month's?"
- **F2.** Standalone MCP server exposing the same tool registry, so Claude Desktop / Claude.ai / future internal tools can use the scheduling surface without the Chat front-end.
- **F3.** Patient/visit awareness — answer "who's visiting Mr. Khan tomorrow?" Out of v1 scope but the matcher in A7 is the natural extension point.
- **F4.** Voice — Chat is text-first, but the same agent could plug into a voice channel (Google Voice / Twilio).
- **F5.** Fairness & load-balancing in A7 — track historical assignment counts and surface "Sara has had 3× the average overnight shifts this month."
- **F6.** Pre-warm thread state from the user's recent calendar so first-question latency is lower.
- **F7.** Org-admin analytics page: per-employee agent usage, top tools called, costs.

---

## 8. Working agreements

- **No bypassing existing services.** Every tool is a thin adapter. If a service can't answer the question, extend the service first; don't write parallel logic in the agent module.
- **Every write is auditable.** A row in `agent_chat_transcripts` *and* whatever audit row the underlying service already produces.
- **Tests gate ✅.** A module is not ✅ in this plan until both the unit + integration tests listed in its section pass and a manual DM was exercised end-to-end.
- **Live API tests are gated.** They never run in CI by default; only when `RUN_LIVE_AI_TESTS=1` is set and `ANTHROPIC_API_KEY` is present.
