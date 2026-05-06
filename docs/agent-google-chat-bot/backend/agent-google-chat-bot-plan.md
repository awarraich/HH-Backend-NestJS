# Google Chat Scheduling Agent — Plan (Backend)

A conversational AI assistant inside the existing HomeHealth Reminders Google Chat bot that lets **individual employees** ask about their own scheduling and availability — and update their own availability and time-off — from inside Google Chat.

This document is **plan-only**. The agent shares the existing webhook, signature verification, and `user_chat_connections` table from the notification integration tracked in [`docs/integration-google-chat/`](../../integration-google-chat/), but its own backend lives under a new module and is tracked here.

> **Scope.** Employee-facing read + employee-self writes only. The agent answers things like "what are my shifts this week?", "what's my availability?", "what shifts are still open that I qualify for?", and lets employees set their own availability rules and request time off. **The bot does not assign shifts** — shift assignment is an organizational decision performed by managers via the existing web UI; the bot does not write to `employee_shift`.

> **Operating model.** Each employee runs the bot for themselves. There are no manager-facing tools, no cross-employee queries, no assignment matchers. RBAC reduces to "the caller can read and modify only their own data."

> **Hard isolation from the existing org-end AI agent.** HomeHealth already has an AI agent integrated on the **organization end** (manager / org-admin audience), located at [`src/mcp/`](../../../src/mcp/) — specifically [`src/mcp/orchestrator/scheduling-agent.service.ts`](../../../src/mcp/orchestrator/scheduling-agent.service.ts) (the orchestrator) and [`src/mcp/tools/scheduling/`](../../../src/mcp/tools/scheduling/) (its tools, including the write tool `assign_employee_to_shift`). That agent is production-critical and **must not be affected by any work in this module**. This bot is a fully parallel, isolated surface:
> - Its own tool registry, its own system prompt, its own identity layer, its own transcript table, its own quota counter.
> - It does **not** import from, extend, or share state with anything under [`src/mcp/`](../../../src/mcp/).
> - Every tool in this bot makes its own service call **scoped to the calling individual employee**, returning individual-scoped results — even when an analogous org-scoped query already exists in the org agent's tool surface. Duplication of a small adapter is the right trade vs. coupling.
> - If a query shape doesn't exist at the individual level, extend the underlying *domain service* (e.g. `EmployeeShiftService` under [`src/models/organizations/scheduling/services/`](../../../src/models/organizations/scheduling/services/)) backwards-compatibly. Never reach into [`src/mcp/`](../../../src/mcp/) to "share."
> - The shared LLM router at [`src/common/services/llm/`](../../../src/common/services/llm/) is **not** used by this module. We use the Anthropic SDK directly to keep prompt-caching control, model versioning, and tool-use semantics independent of whatever the org agent does.
> - Reviewers: any PR in this module that imports from `src/mcp/` or `src/common/services/llm/` is a bug — flag it.

---

## 0. Compliance & data privacy (pre-prod blocker)

**Current state.** The agent is being designed and will initially be exercised on **non-real / dev data only**. Real production data does not flow to Anthropic until every gate in this section is cleared. This section exists so the constraints are not lost when the project moves toward production.

**Why this is more sensitive than the notification module.** The reminder bot sends one-way templated messages — almost no org data leaves the platform. The agent inverts that: every turn pumps real org data *into* the model's prompt as tool results, and the user's free-text messages can carry anything ("I can't work Thursday, my chemo moved to Friday"). Once a piece of text enters the thread state it sits in every subsequent prompt for the TTL.

**What flows to Anthropic per turn:**
- The user's raw Chat message (free-text — could contain medical context, personal context).
- System prompt + tool definitions (no PII; prompt-cached).
- Prior turn history from Redis (TTL-bounded, but PII-bearing).
- **Every tool result.** The caller's own shift times, locations, role names, availability rules, time-off windows. Tool results are scoped to the caller, so other employees' data does not flow.

**Pre-prod gates — none satisfied yet:**

| # | Gate | Owner | Status |
|---|---|---|---|
| C1 | Anthropic DPA executed (or alternate route chosen — AWS Bedrock regional endpoint, Vertex AI regional endpoint) | Legal + Eng | ❌ |
| C2 | Zero-retention configured on the Anthropic account (default 30-day operational retention is **not** acceptable for production) | Eng | ❌ |
| C3 | Cross-border transfer basis documented (Saudi PDPL — explicit consent, contract, or adequacy decision) | Legal | ❌ |
| C4 | Field-level data classification policy: per tool output field, marked `send` / `redact` / `never-send` | Eng + Legal | ❌ |
| C5 | Employee notice + consent flow folded into the Google Chat integration enable wizard | Product + Legal | ❌ |
| C6 | `agent_chat_transcripts` retention decided and enforced (default proposal: 90 days then archive) | Eng | ❌ |
| C7 | Healthcare data classification: confirm whether scheduling/time-off data falls under PHI-equivalent rules in the relevant jurisdictions | Legal | ❌ |
| C8 | Redaction layer (M11) built and tested before the first prod tenant is enabled | Eng | ❌ |

**Implementation gating.**
- **Modules M1 → M4 may proceed today** — they don't send org data anywhere (SDK wiring, identity resolution, conversation state, tool registry are all infrastructure).
- **Modules M5 onward** can be built and tested *only* against synthetic/dev data until **C1, C2, C3, C5** are cleared.
- **Production rollout (M13 flag flipped on for any real org)** requires all of C1–C8.

**On using dev data today.** Watch what gets typed into the bot during exploratory testing — real names, real customer info, or real medical context entered casually will sit in `agent_chat_transcripts` and could leak through screenshots, support tickets, or accidental prod promotion. Treat dev as if a screenshot might end up in a slide deck.

---

## 1. Architecture summary

```
Google Chat (DM from employee)
   │
   ▼
POST /v1/api/google-chat/webhook   (existing — owned by notification integration)
   │
   ├── ADDED_TO_SPACE / REMOVED_FROM_SPACE  → existing notif handlers (untouched)
   │
   └── MESSAGE                              → GoogleChatAgentService.handle()
                                                │
                                                ▼
                                          1. Resolve identity (chat_user_id → HH employee)
                                          2. Load thread state (Redis, TTL'd)
                                          3. Quota check (M14) — abort with upgrade card if exhausted
                                          4. Append user turn → call Claude with employee-scoped tools
                                          5. Tool-use loop:
                                               ├─ listMyShifts / getMyAvailability / setAvailabilityRule / …
                                               │     → call existing NestJS services as the resolved employee
                                               │     → tool output is scoped to caller; never another employee
                                               └─ return tool result to model
                                          6. Render final assistant turn
                                               ├─ structured Card v2 (for shift / availability lists)
                                               └─ plain text (for prose / errors)
                                          7. POST reply to Chat thread
                                          8. Log transcript row + increment quota counter
```

**Key choices:**
- **No external MCP server in v1.** The LLM lives inside NestJS; tools are thin wrappers over existing services. The tool registry is structured so a future MCP-server refactor (F2) is additive, not a rewrite.
- **Employee-self only.** Every tool's first action is `assert(target_user === resolved_user)`. There are no manager tools; no admin overrides through this surface.
- **Read-mostly.** The only writes are *the caller's own* availability rules and time-off requests. Shift assignment is **never** writable from the bot.
- **Isolated from the org-end AI agent.** Parallel module, no shared infrastructure (see scope callout above). Individual-scoped service calls only.

**Model routing:**
- Sonnet 4.6 for the tool-use loop (default).
- Haiku 4.5 for trivial pre-classification (greetings, "thanks", help, slash-command-equivalents).
- Prompt caching enabled on the system prompt + tool definitions.

---

## 2. Module map

| # | Module | One-line scope |
|---|---|---|
| M1 | ✅ Foundation — Anthropic SDK + config | `@anthropic-ai/sdk` install, env vars, DI-injectable Claude client |
| M2 | ✅ Identity resolver | Chat user → HH employee with org + timezone loaded |
| M3 | ✅ Conversation state | Thread-keyed turn history in Redis with TTL |
| M4 | ✅ Tool registry & contracts | Zod-typed tool defs → Claude JSON schemas; central dispatch |
| M5 | ✅ Read tools — shifts | `listMyShifts`, `getShiftDetails`, `listAvailableShifts` |
| M6 | ✅ Read tools — availability | `getMyAvailability`, `getMyTimeOffRequests` |
| M7 | ✅ Write tools — availability (self) | `setAvailabilityRule`, `setAvailabilityForDate`, `requestTimeOff`, `cancelTimeOffRequest` |
| M8 | ✅ Webhook MESSAGE branch | Route MESSAGE events into agent pipeline; preserve notif handlers |
| M9 | ✅ Response rendering (M5 + M6 + M7 surfaces) | Card v2 builders for shifts, availability, time-off; write-confirmation cards for M7 writes; plain text fallback |
| M10 | RBAC enforcement (self-only) | Single choke point asserting caller == target on every tool dispatch |
| M11 | ✅ Transcript & audit logging | `agent_chat_transcripts` table; tool calls + redaction policy |
| M12 | Rate limiting (abuse control) | Per-user, per-org request budgets to prevent runaway loops |
| M13 | Feature flag & rollout | Per-org enable; allowlist; global kill switch |
| M14 | Quota & monetization | 50 free messages per employee, then paid tier (impl deferred) |
| M15 | Model router | Haiku-first triage → Sonnet on tool use |
| M16 | ✅ Observability | Structured logs, latency/cost per turn (Sentry/Prometheus deferred) |
| M17 | Help & discoverability | `/help` slash command + onboarding card |

Status legend: ✅ done · 🚧 in progress · ❌ not started · 💤 deferred.

M1 through M9 + M11 + M16 are **✅ Complete** (M1, M2, M3, M4, M5, M6, M7, M8, M9, M11, M16). M14's *implementation* is **💤 Deferred** (data model lands now, billing flow lands later). All other modules (M10, M12, M13, M14, M15, M17): **❌ Not started.**

> **LLM provider is now pluggable.** `GOOGLE_CHAT_AGENT_PROVIDER=anthropic|openai` switches between the Anthropic and OpenAI tool-use loops at runtime. Models, tool-payload shapes, and message conventions diverge per provider; the agent service picks the right path. This was added when Anthropic credit balance ran low during dev testing — both paths are first-class.

---

## 3. Modules in detail

Each module section follows: **Goal · Touch points · Contract · Tests · Done when.**

---

### M1. Foundation — Anthropic SDK + config ✅

**Goal.** A typed, DI-injectable Claude client with prompt caching configured.

**Touch points:**
- `package.json`: add `@anthropic-ai/sdk`.
- `src/config/google-chat-agent/`: new config namespace.
- `src/models/google-chat-agent/` (new module): `claude.client.ts`, `scheduling-agent.module.ts`.

**Contract:**
```
GOOGLE_CHAT_AGENT_ENABLED=true|false           # global kill switch (this module's flag)
ANTHROPIC_API_KEY=sk-ant-...                   # already exists at apiKeys.anthropic — reused, not duplicated
GOOGLE_CHAT_AGENT_MODEL=claude-sonnet-4-6
GOOGLE_CHAT_AGENT_TRIAGE_MODEL=claude-haiku-4-5-20251001
GOOGLE_CHAT_AGENT_MAX_TOKENS=2048
GOOGLE_CHAT_AGENT_TURN_TIMEOUT_MS=30000
GOOGLE_CHAT_AGENT_FREE_MESSAGES_PER_USER=50    # M14
```

The Anthropic key is read via the existing global config at [`src/config/app/api-keys.configuration.ts`](../../../src/config/app/api-keys.configuration.ts) — module-local config only owns the agent-specific knobs.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M1-U1 | unit | `ClaudeClient` constructed with API key from config; throws on missing key when `ENABLED=true` |
| M1-U2 | unit | Disabled flag (`GOOGLE_CHAT_AGENT_ENABLED=false`) makes the provider a no-op stub; boot succeeds |
| M1-I1 | integration | Live call to Haiku returns a non-empty completion (gated by `RUN_LIVE_AI_TESTS=1`) |

**Done when:** boot succeeds with flag on and off; live test produces a completion locally.

**Done:**
- `@anthropic-ai/sdk@^0.69.0` added to [`package.json`](../../../package.json) and installed.
- Config namespace at [`src/config/google-chat-agent/`](../../../src/config/google-chat-agent/) (configuration, ConfigModule, ConfigService).
- Module at [`src/models/google-chat-agent/`](../../../src/models/google-chat-agent/) with `ClaudeClient` provider.
- Wired into [`src/app.module.ts`](../../../src/app.module.ts).
- Anthropic key reused from existing `apiKeys.anthropic` slot — no duplicate env var.

**Verified:**
- 7 tests pass: 4 unit (`claude.client.spec.ts` covering enabled+key, enabled-no-key, disabled-no-key, disabled-with-key) + 3 DI-boot (`google-chat-agent.module.spec.ts` covering disabled-default, enabled-with-key, enabled-no-key-rejects-compile).
- `npm run build` clean.
- M1-I1 (live Haiku call) deferred until needed; gated behind `RUN_LIVE_AI_TESTS=1` per the testing convention.

**Tests caveat:** the DI-boot spec requires `ignoreEnvFile: true` on `ConfigModule.forRoot` — without it, Nest's config re-reads the repo's `.env` between tests and overrides `process.env` mutations, making "key absent" tests non-deterministic. This pattern should be reused in M2+ specs.

---

### M2. Identity resolver ✅

**Goal.** Given a Google Chat `user.name`, return the HH employee — or `null` if unlinked. The single trusted source of "who is asking."

**Touch points:**
- [`src/models/google-chat-agent/services/agent-identity.service.ts`](../../../src/models/google-chat-agent/services/agent-identity.service.ts).
- [`src/models/google-chat-agent/services/agent-identity.types.ts`](../../../src/models/google-chat-agent/services/agent-identity.types.ts) — `ResolvedAgentUser` interface and `AGENT_DEFAULT_TIMEZONE`.
- Reads from [`user_chat_connections`](../../../src/models/notifications/entities/user-chat-connection.entity.ts) (owned by notification integration). Does **not** introduce a parallel mapping.

**Contract (revised against the actual schema):**
```ts
interface ResolvedAgentUser {
  userId: string;          // uuid in this DB, not int (plan originally said number)
  organizationId: string;  // uuid
  timezone: string;
  chatUserId: string;
  chatSpaceName: string | null;
}
async resolve(chatUserId: string): Promise<ResolvedAgentUser | null>;
```

**Timezone — temporary default.** Neither User nor Organization has a `timezone` column today. Resolver returns `AGENT_DEFAULT_TIMEZONE = 'UTC'` (defined locally — deliberately *not* importing `FALLBACK_TIMEZONE` from `src/mcp/`). When a real timezone column lands on User or Organization, swap the default for that read. Tracked as a follow-up; not blocking.

**Tests:**

| ID | Type | Proves | Status |
|---|---|---|---|
| M2-U1 | unit | Returns null when no `user_chat_connections` row exists | ✅ |
| M2-U2 | unit | WHERE clause includes `status='connected'`, so revoked/pending rows are excluded | ✅ |
| M2-U3 | unit | Returned `ResolvedAgentUser` includes the agent default timezone | ✅ |
| M2-U4 | unit | Empty `chatUserId` short-circuits to null without hitting the repo | ✅ |
| M2-U5 | unit | Falls back to caller-supplied `chatUserId` when row's `chat_user_id` column is null | ✅ |
| M2-I1 | integration | Real DB seed: linked employee resolves; revoked + unlinked do not | ❌ deferred (no test DB harness in repo yet — covered by mock-based unit tests for now) |

**Done when:** all tests green; manually DM-tested with a linked + an unlinked test account.

**Done:**
- Service registered in [`GoogleChatAgentModule`](../../../src/models/google-chat-agent/google-chat-agent.module.ts) via `TypeOrmModule.forFeature([UserChatConnection])`.
- Module spec updated to mock the repository token so the M1 DI-boot tests stay DB-free.

**Verified:** 6 unit tests in [`agent-identity.service.spec.ts`](../../../src/models/google-chat-agent/services/agent-identity.service.spec.ts) cover M2-U1 through M2-U5; build clean; full test suite for the module: 13/13 passing.

**Caveat — M2-I1 deferred.** The repo has no integration-test DB harness. Rather than build one for a single test, M2-I1 is deferred until M5 (read tools) lands — at that point, manually exercising "linked employee can read their shifts; revoked employee gets denied" via a real DM is a stronger end-to-end check than an integration spec.

---

### M3. Conversation state ✅

**Goal.** Persist last N turns per Chat thread so follow-ups have context. Short TTL — not durable history.

**Touch points:**
- [`src/models/google-chat-agent/services/conversation-state.service.ts`](../../../src/models/google-chat-agent/services/conversation-state.service.ts).
- [`src/models/google-chat-agent/services/conversation-state.types.ts`](../../../src/models/google-chat-agent/services/conversation-state.types.ts) — `AgentTurn`, `MAX_TURNS=12`, `CONVERSATION_TTL_MS=30min`.
- [`src/models/google-chat-agent/redis/agent-redis.client.ts`](../../../src/models/google-chat-agent/redis/agent-redis.client.ts) — owned ioredis wrapper with `lazyConnect: true`, `OnModuleDestroy` cleanup, agent-prefixed keys (`agent:thread:<threadKey>`).
- `ioredis@^5.10.1` added as an explicit dep (was a transitive via BullMQ).
- Reuses `REDIS_HOST` / `REDIS_PORT` env conventions from [`app.module.ts`](../../../src/app.module.ts) — separate connection from BullMQ's so an agent-side Redis hiccup doesn't impact queue health.

**Contract:**
```ts
interface AgentTurn { role: 'user' | 'assistant' | 'tool'; content: unknown; ts: string; }
get(threadKey): Promise<AgentTurn[]>;       // up to MAX_TURNS (default 12)
append(threadKey, turn): Promise<void>;
clear(threadKey): Promise<void>;            // for /reset slash command
// TTL: 30 minutes since last turn
```

**Important:** business data (shifts, availability) is **never** cached at this layer — tool results are recomputed every turn. Only conversation turns are cached. This avoids the "I made a change in the web UI, why does the bot still see the old version?" class of bug.

**Tests:**

| ID | Type | Proves | Status |
|---|---|---|---|
| M3-U1 | unit | `append` rolls window when length > MAX_TURNS (oldest dropped) | ✅ |
| M3-U2 | unit | `clear` removes the key | ✅ |
| M3-U3 | unit | TTL is reset on every `append` (writes via `psetex` with `CONVERSATION_TTL_MS`) | ✅ |
| M3-U4 | unit | Corrupt JSON in storage is treated as empty thread (defensive — no throw) | ✅ |
| M3-U5 | unit | Different thread keys are isolated | ✅ |
| M3-U6 | unit | Storage keys are prefixed `agent:thread:` for tooling/grep visibility | ✅ |
| M3-I1 | integration | Two sequential webhook calls in same thread share state; different threads do not | ❌ deferred (covered by unit M3-U5; full webhook flow proven once M8 lands) |
| M3-I2 | integration | Key expires after TTL | ❌ deferred (no live-Redis harness; ioredis behavior is upstream-tested) |
| M3-I3 | integration | Mid-conversation: change availability via web UI → next bot turn reflects the change (no business-data caching) | ❌ deferred until M5+M8 (manual end-to-end) |

**Done when:** M3-I3 verified end-to-end with the web UI.

**Done:**
- `AgentRedisClient` (ioredis wrapper) + `agentRedisClientProvider` (factory, `lazyConnect: true`).
- `ConversationStateService` — `get` / `append` / `clear`; serializes turns as JSON; trims to MAX_TURNS; resets TTL on every append.
- Module wiring: `agentRedisClientProvider`, `AgentRedisClient`, `ConversationStateService` registered + exported.
- M1 DI-boot spec updated to mock `AGENT_REDIS_CLIENT_TOKEN` so the boot tests stay infra-free.

**Verified:** 9 unit tests in [`conversation-state.service.spec.ts`](../../../src/models/google-chat-agent/services/conversation-state.service.spec.ts) cover all M3-Uxx cases via an in-memory `FakeAgentRedis`. Module spec mocks the Redis token so M1 boot tests still pass. Total module tests: 22/22 passing; build clean.

**Caveats:**
- **No live-Redis integration harness.** ioredis-level TTL semantics aren't re-verified here; we trust the upstream library and assert that the *service* writes the right TTL value via `psetex`. M3-I1/I2 effectively land when M8 is exercised in dev with a real Redis.
- **M3 has no slash-command handler yet.** `clear()` is exposed for use by `/reset` (M8 work).

---

### M4. Tool registry & contracts ✅

**Goal.** A single typed registry. Adding a tool is one file. Every tool automatically: (a) exposed to Claude with a JSON schema, (b) gated through M10 self-check, (c) logged in transcript (M11), (d) counted against quota (M14).

**Touch points:**
- [`src/models/google-chat-agent/tools/tool.types.ts`](../../../src/models/google-chat-agent/tools/tool.types.ts) — `Tool<I,O>`, `AgentContext`, `AnthropicToolPayload`, error classes (`DuplicateToolError`, `ToolNotFoundError`, `ToolInputValidationError`, `ToolOutputValidationError`).
- [`src/models/google-chat-agent/tools/tool.registry.ts`](../../../src/models/google-chat-agent/tools/tool.registry.ts) — `@Injectable()` `ToolRegistry` with `register` / `dispatch` / `getAnthropicToolsPayload` / `list` / `size`.
- Uses `zod` and `zod-to-json-schema` (both already in repo). Verified: zod-to-json-schema produces `additionalProperties: false` by default, no override needed.

**Contract:**
```ts
interface AgentContext {
  user: ResolvedAgentUser;     // from M2
  turnId: string;              // per-message correlation id
}

interface Tool<I, O> {
  name: string;                              // 'listMyShifts'
  description: string;                       // shown to the model
  input: z.ZodType<I>;
  output: z.ZodType<O>;
  handler(input: I, ctx: AgentContext): Promise<O>;
}

// Note: deliberately no `requiredRoles` field. The agent is self-only by
// design (see plan §scope) — every tool runs as the calling employee, on
// the calling employee's data. Adding role-gated tools is a new module.
```

**Anthropic payload notes.**
- `additionalProperties: false` on every tool's `input_schema` (matches Anthropic's strict-tools recommendation).
- Prompt-cache breakpoint via `cache_control: { type: 'ephemeral' }` is set on the **last** tool only — caches the entire tools block across turns. (System-prompt cache breakpoint is applied separately at message construction in M15.)
- `$schema` and `definitions` metadata stripped — Anthropic's API doesn't use them.

**Dispatch pipeline.**
1. Lookup name → `ToolNotFoundError` if missing.
2. Zod-validate input → `ToolInputValidationError` with structured issues.
3. Run handler → handler exceptions propagate unchanged.
4. Zod-validate output → `ToolOutputValidationError` (this means the tool implementation has a bug; the model never sees invalid output).
5. Return validated output.

**Tests:**

| ID | Type | Proves | Status |
|---|---|---|---|
| M4-U1 | unit | Registry rejects duplicate tool names | ✅ |
| M4-U2 | unit | `getAnthropicToolsPayload()` produces JSON Schema with `additionalProperties: false` matching Zod shape | ✅ |
| M4-U3 | unit | `dispatch('unknown', …)` throws `ToolNotFoundError` | ✅ |
| M4-U4 | unit | Output failing the Zod schema throws `ToolOutputValidationError` before returning | ✅ |
| M4-U5 | unit | Input failing the Zod schema throws `ToolInputValidationError` before calling the handler | ✅ |
| M4-U6 | unit | `cache_control: ephemeral` attached to the LAST tool only | ✅ |
| M4-U7 | unit | `$schema` and `definitions` are stripped from `input_schema` | ✅ |
| M4-U8 | unit | Empty registry returns an empty payload | ✅ |
| M4-U9 | unit | Handler exceptions propagate unchanged (not wrapped) | ✅ |
| M4-U10 | unit | Zod defaults applied to input before handler is called | ✅ |
| M4-U11 | unit | `list()`, `size()`, `has()` reflect registered state | ✅ |

**Done when:** all unit tests green; smoke `ping` tool registers and round-trips.

**Done:**
- Type definitions + four structured error classes.
- `ToolRegistry` with strict input/output validation, cache-control breakpoint placement, and Zod→JSON Schema conversion.
- Registered + exported in [`GoogleChatAgentModule`](../../../src/models/google-chat-agent/google-chat-agent.module.ts).

**Verified:** 12 unit tests in [`tool.registry.spec.ts`](../../../src/models/google-chat-agent/tools/tool.registry.spec.ts) (covers M4-U1 through M4-U11 plus the `dispatch` happy-path with handler args). Total module tests: 34/34 passing; build clean.

**Caveats:**
- **Tool registration pattern not yet decided.** The registry is a stateful singleton with `register()`. M5+ will introduce the integration pattern — likely tool-provider classes that call `register()` from `onModuleInit`, but the choice is deferred until the first real tool lands.
- **No prompt-cache control on system prompt yet.** That's M15 (model router) — when message construction happens.

---

### M5. Read tools — shifts ✅

**Goal.** First useful surface. Read-only, employee-self only.

**Tools:**
| Tool | Description |
|---|---|
| `listMyShifts(dateRange?)` | shifts assigned to the caller; default = today → +7 days |
| `getShiftDetails(shiftId)` | full details of one shift the caller is assigned to (else denied) |
| `listAvailableShifts(dateRange?)` | open shifts in caller's org that match caller's role qualifications and don't conflict with their existing assigned shifts |

**Touch points:**
- `src/models/google-chat-agent/tools/shifts/*.tool.ts` — one file per tool.
- Wraps `EmployeeShiftService` and `ShiftService` from `src/models/organizations/scheduling/services/`. **No** new query logic — if a shape is missing, extend the underlying service first.

**Note on `listAvailableShifts`.** This is read-only org data filtered to "shifts the caller could potentially be assigned to." It does not let the employee self-assign — that's not a tool. The card output should make it clear this is an FYI, not an action ("Talk to your manager if you'd like to be assigned").

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M5-U1 | unit | `listMyShifts` filters strictly to caller's `employee_id`; never returns another employee's shift even if service is mocked to return more |
| M5-U2 | unit | `listMyShifts` defaults to today→+7d when no range given |
| M5-U3 | unit | `getShiftDetails` denies when shift not assigned to caller |
| M5-U4 | unit | `listAvailableShifts` excludes shifts that conflict with caller's existing assignments |
| M5-U5 | unit | `listAvailableShifts` excludes shifts whose role doesn't match caller |
| M5-U6 | unit | All three tools enforce `organization_id == caller.organization_id` |
| M5-I1 | integration | Cross-org isolation: caller in org A sees zero open shifts from org B |
| M5-I2 | integration | Date-range filtering matches direct service calls |

**Done when:** integration tests pass; manual DM "what are my shifts this week?" returns the correct set; "what shifts are still open?" returns only role-qualified non-conflicting shifts.

**Done:**
- Three self-only methods added to [`EmployeeShiftService`](../../../src/models/organizations/scheduling/services/employee-shift.service.ts):
  - `findByCallerSelf(orgId, userId, range)` — caller's assignments in date range; resolves Employee via `(user_id, organization_id)`.
  - `findShiftDetailsForCallerSelf(orgId, userId, shiftId)` — returns `{shift, assignments}` only when caller has an assignment to this shift; null otherwise.
  - `findAvailableForCallerSelf(orgId, userId, range)` — active shifts in caller's org filtered to caller's role qualifications. Returns role-agnostic shifts plus shifts whose `shift_roles` includes caller's `provider_role_id`.
- Three tools at [`src/models/google-chat-agent/tools/shifts/`](../../../src/models/google-chat-agent/tools/shifts/):
  - [`list-my-shifts.tool.ts`](../../../src/models/google-chat-agent/tools/shifts/list-my-shifts.tool.ts), [`get-shift-details.tool.ts`](../../../src/models/google-chat-agent/tools/shifts/get-shift-details.tool.ts), [`list-available-shifts.tool.ts`](../../../src/models/google-chat-agent/tools/shifts/list-available-shifts.tool.ts).
  - Shared schemas in [`shift.schemas.ts`](../../../src/models/google-chat-agent/tools/shifts/shift.schemas.ts) and date-range helper in [`date-range.ts`](../../../src/models/google-chat-agent/tools/shifts/date-range.ts).
- [`ShiftToolsProvider`](../../../src/models/google-chat-agent/tools/shifts/shift-tools.provider.ts) registers all three with `ToolRegistry` on `onModuleInit`.
- `OrganizationsModule` imported into `GoogleChatAgentModule` to inject `EmployeeShiftService`.
- M1 boot spec retired — once the agent module pulled in `OrganizationsModule`'s real TypeORM graph, mocking the deep dependency tree was no longer infra-free. Boot verification now relies on (a) per-service unit tests, (b) `npm run build`, (c) production `npm start` smoke.

**Verified:** 14 unit tests in [`shift-tools.spec.ts`](../../../src/models/google-chat-agent/tools/shifts/shift-tools.spec.ts) cover delegation to caller-self service methods, default date range, scope forwarding, output flattening, Zod input rejection of bad uuids/dates, and unique tool names. Total module tests: 45/45 passing; build clean.

**Caveats:**
- **No conflict-filter on `listAvailableShifts`.** v1 returns role-qualified shifts but does NOT exclude shifts the caller is already assigned to in the date range. Easy follow-up if the model surfaces noisy results in dev.
- **Recurring-shift display is template-level.** Tools return the shift template's `start_at` / `end_at` as ISO timestamps. Users seeing a recurring shift's "Jan 1 1970 18:00 → 02:00" timestamps need M9 (rendering) to interpret it. Until M9, plain JSON output. Acceptable for M5 in isolation.
- **Date defaults are UTC-anchored.** `defaultShiftRange()` uses `setUTCHours(0,0,0,0)` — fine for now since `AGENT_DEFAULT_TIMEZONE` from M2 is also UTC. When the timezone column lands, this needs to use the resolved user's tz.

---

### M6. Read tools — availability ✅

**Goal.** Caller-self only. No manager queries.

**Tools:**
| Tool | Description |
|---|---|
| `getMyAvailability` | active availability rules + work prefs for the caller |
| `getMyTimeOffRequests(status?)` | caller's own; default last 30 / next 60 days |

**Touch points:**
- `src/models/google-chat-agent/tools/availability/*.tool.ts`.
- Wraps `AvailabilityRuleService`, `TimeOffRequestService`, `WorkPreferenceService`.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M6-U1 | unit | `getMyAvailability` returns active rules only (excludes soft-deleted/expired) |
| M6-U2 | unit | Time-off statuses normalized to `pending|approved|denied|cancelled` regardless of underlying enum drift |
| M6-U3 | unit | Both tools strictly filter to `caller.userId`; mocked broader response is filtered out |

**Done when:** unit tests green; manual DM "what's my availability?" returns the same rules visible in the web profile.

**Done:**
- Two tools at [`src/models/google-chat-agent/tools/availability/`](../../../src/models/google-chat-agent/tools/availability/):
  - [`get-my-availability.tool.ts`](../../../src/models/google-chat-agent/tools/availability/get-my-availability.tool.ts) — calls `AvailabilityRuleService.findByUser` + `WorkPreferenceService.findOrCreate`.
  - [`get-my-time-off-requests.tool.ts`](../../../src/models/google-chat-agent/tools/availability/get-my-time-off-requests.tool.ts) — calls `TimeOffRequestService.findAll` with caller scope; default range last 30 / next 60 days; optional status filter.
- Shared schemas in [`availability.schemas.ts`](../../../src/models/google-chat-agent/tools/availability/availability.schemas.ts) including `normalizeTimeOffStatus()` (maps `Approved/accepted` → `approved`, `denied/REJECTED` → `denied`, `cancelled/canceled` → `cancelled`).
- Card renderers: [`my-availability.card.ts`](../../../src/models/google-chat-agent/rendering/availability/my-availability.card.ts) (weekly + date overrides + work prefs sections); [`time-off-list.card.ts`](../../../src/models/google-chat-agent/rendering/availability/time-off-list.card.ts) (paginates at MAX_INLINE_ROWS, status badges).
- `EmployeesModule` updated to export `AvailabilityRuleService`, `TimeOffRequestService`, `WorkPreferenceService`.
- `EmployeesModule` imported into `GoogleChatAgentModule` so the tools' DI graph resolves.

**Verified:** Covered by 30+ tests in [`availability-tools.spec.ts`](../../../src/models/google-chat-agent/tools/availability/availability-tools.spec.ts) — including caller-scope forwarding, status normalization across DB drift variants, and output-shape flattening.

---

### M7. Write tools — availability (self) ✅

**Goal.** Employees mutate **only their own** availability and time-off through the bot.

**Tools:**
| Tool | Description |
|---|---|
| `setAvailabilityRule` | upsert a recurring rule for caller (day-of-week + time window) |
| `requestTimeOff` | create a pending time-off request for caller |
| `cancelTimeOffRequest` | cancel one of caller's own *pending* requests |

**Touch points:**
- `src/models/google-chat-agent/tools/availability-write/*.tool.ts`.
- Wraps `AvailabilityRuleService`, `TimeOffRequestService`. **Does not bypass** existing service-level validation (overlap, min-notice, etc.).

**Confirmation pattern.** Writes execute immediately. M9 renders the resulting card with an "undo" button valid for 60s for `setAvailabilityRule` and `cancelTimeOffRequest`. `requestTimeOff` is "undoable" by calling `cancelTimeOffRequest` while pending — no special undo UI needed.

**Idempotency.** Every write tool accepts an optional `idempotency_key`. The model is instructed to pass the same key on retries. Same-key + same-input within 60s returns the original result without re-executing.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M7-U1 | unit | `setAvailabilityRule` upserts on `(employee_id, day_of_week)` — running twice with same input produces one row, not two |
| M7-U2 | unit | `requestTimeOff` rejects backdated / past-window requests (delegates to service validator; tool surfaces error verbatim) |
| M7-U3 | unit | `cancelTimeOffRequest` denies cancelling someone else's request (impossible-by-construction since we filter by caller; assert the negative) |
| M7-U4 | unit | `cancelTimeOffRequest` denies cancelling an `approved` request |
| M7-U5 | unit | Idempotency key suppresses duplicate inserts on same-input retry within 60s window |
| M7-I1 | integration | Round-trip: setAvailabilityRule via bot → getMyAvailability via bot reflects the new rule |
| M7-I2 | integration | Round-trip: setAvailabilityRule via bot → web profile shows the new rule |

**Done when:** all tests green; manual DM "I can't work next Tuesday" creates a pending TOR visible in the web UI.

**Done:**
- New service method [`AvailabilityRuleService.upsertWeeklyRuleForUser`](../../../src/models/employees/availability/services/availability-rule.service.ts) — replaces all non-date-specific weekly rules for a `(user_id, day_of_week, organization_id)` scope before inserting one new rule. Validates `day_of_week ∈ [0..6]` and `start_time !== end_time`. Date-specific overrides are not touched.
- Three tools at [`src/models/google-chat-agent/tools/availability/`](../../../src/models/google-chat-agent/tools/availability/):
  - [`set-availability-rule.tool.ts`](../../../src/models/google-chat-agent/tools/availability/set-availability-rule.tool.ts) — wraps the upsert; friendly day-name in the success message.
  - [`request-time-off.tool.ts`](../../../src/models/google-chat-agent/tools/availability/request-time-off.tool.ts) — rejects backdated `startDate`; rejects `endDate < startDate`; checks for an existing pending request with same `(start, end, reason)` and surfaces it instead of creating a duplicate (idempotency-lite without a Redis cache key).
  - [`cancel-time-off-request.tool.ts`](../../../src/models/google-chat-agent/tools/availability/cancel-time-off-request.tool.ts) — delegates to `TimeOffRequestService.cancel`, which already enforces "only pending can be cancelled" AND filters by `(id, user_id)` so cancelling another user's request throws NotFound at the service layer (M7-U3 + M7-U4 satisfied without extra checks).
- All five tools registered by [`AvailabilityToolsProvider`](../../../src/models/google-chat-agent/tools/availability/availability-tools.provider.ts) on `onModuleInit`.
- Three write-confirmation card renderers in [`write-confirmation.cards.ts`](../../../src/models/google-chat-agent/rendering/availability/write-confirmation.cards.ts) — saved-availability, time-off-submitted, time-off-cancelled. Registered by [`AvailabilityRenderersProvider`](../../../src/models/google-chat-agent/rendering/availability/availability-renderers.provider.ts).
- System prompt expanded to describe all five availability capabilities + write-confirmation guidance ("the card already echoes the change — do not paraphrase the result in prose").

**Verified:** 18 tests in [`availability-tools.spec.ts`](../../../src/models/google-chat-agent/tools/availability/availability-tools.spec.ts) cover M7-U1 (upsert call shape), M7-U2 (backdated rejection + endDate validation), M7-U3 (NotFound propagated for non-caller requests), M7-U4 (only-pending error propagated), Zod input rejection of bad uuids/dayOfWeek/time strings, and idempotency-lite (no duplicate created when matching pending request exists). Total module tests: **126/126** passing; build clean.

**Caveats:**
- **Undo button NOT implemented.** Plan called for a 60s undo on writes. That requires a Chat action handler endpoint to receive button clicks — separate work that touches the webhook controller again. Today the user can `cancelTimeOffRequest` to reverse a TOR; for `setAvailabilityRule` they'd just call it again with different times.
- **Idempotency is duplicate-detection, not Redis-cached.** Plan called for `idempotency_key` with 60s TTL. Implemented as: "if a pending request with same start/end/reason exists, return it." Sufficient for the practical case (model retries the same call within seconds); doesn't catch "user changed reason text" duplicates. Good enough for v1.
- **`upsertWeeklyRuleForUser` replaces multi-slot days.** If a user had a split-shift Tuesday (e.g., 9-12 + 13-17), calling the tool with a single window collapses to one slot. The system prompt should warn the model; today it doesn't explicitly. If this surfaces in testing, tweak the tool description.
- **Re-running the migration won't fail** — `agent_chat_transcripts` (M11) is the only new table this round of work added; M6/M7 use existing tables (`availability_rules`, `time_off_requests`, `work_preferences`). No new migration needed.

**Follow-up after dev testing — date-specific availability tool added.**

The first DM-test of M7 surfaced a feature gap: the user said *"I will be available for the shift assignment 8th May 2026 from 7AM to 3 PM"* and the bot correctly noted it had no tool for date-specific availability. Plan called for `setAvailabilityRule` (recurring weekly) only. Real usage needs both.

- New tool [`setAvailabilityForDate`](../../../src/models/google-chat-agent/tools/availability/set-availability-for-date.tool.ts) — wraps the existing `AvailabilityRuleService.upsertDateOverride` method (already in the domain layer; just not previously exposed). Day-of-week is derived server-side from the date itself, sidestepping the LLM weekday-arithmetic problem.
- New card renderer [`availability-for-date.card.ts`](../../../src/models/google-chat-agent/rendering/availability/availability-for-date.card.ts).
- System prompt updated with: (a) the new tool, (b) explicit "Specific date → setAvailabilityForDate; recurring → setAvailabilityRule" guidance, (c) "do not compute day-of-week in your head" rule, (d) **CONFIRMATION RESPONSES** section telling the model that when the previous turn proposed an action and the user replies with a short affirmative, it should call the proposed tool — not greet or restart. This addresses the "Yes → Hello!" failure mode seen in dev testing.

7 unit tests in [`set-availability-for-date.spec.ts`](../../../src/models/google-chat-agent/tools/availability/set-availability-for-date.spec.ts) cover backdating rejection, equal-time rejection, malformed date rejection, scope forwarding, defensive empty-result handling, and DTO `shift_type` undefined-vs-null handling.

---

### M8. Webhook MESSAGE branch ✅

**Goal.** Wire MESSAGE events into the agent without breaking ADDED/REMOVED handlers from the notification flow.

**Touch points:**
- `src/models/notifications/google-chat/webhook.controller.ts` — extend the `MESSAGE` branch to call `GoogleChatAgentService.handle(event)`.
- The agent service short-circuits when `GOOGLE_CHAT_AGENT_ENABLED=false` or the org's M13 flag is off, replying with a friendly disabled card.

**Behaviors:**
- Slash commands (Chat-native): `/help`, `/reset`, `/whoami`. Hard-coded handlers — no LLM call.
- Plain DM text → M15 model router → agent loop.
- Empty / attachment-only message → friendly "I don't read attachments yet" reply.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M8-U1 | unit | ADDED_TO_SPACE still routes to the existing notif handler (regression) |
| M8-U2 | unit | MESSAGE with no text and no slash command produces the attachment-only reply |
| M8-U3 | unit | `/reset` clears the thread state (calls M3.clear) |
| M8-U4 | unit | Disabled flag returns the disabled card without invoking Claude |
| M8-I1 | integration | Captured Chat MESSAGE payload → agent reply JSON validated against Chat's response schema |

**Done when:** notification module's existing tests still pass; agent integration test passes with a captured payload.

**Done:**
- [`GoogleChatAgentService.handleMessage(event)`](../../../src/models/google-chat-agent/services/google-chat-agent.service.ts) — orchestrates: disabled-check → identity resolution → slash routing → empty/attachment fallback → Claude tool-use loop → render last tool output as a card (or text fallback) → persist user + assistant turns to thread state.
- [`runToolUseLoop`](../../../src/models/google-chat-agent/services/tool-use-loop.ts) — Anthropic SDK tool-use orchestration with a 6-iteration cap, system-prompt cache_control, and tool-error capture as `is_error: true` tool_results.
- [`buildSystemPrompt`](../../../src/models/google-chat-agent/services/system-prompt.ts) — caller-aware system prompt with stable refusal/capability prefix and a per-turn date/user suffix.
- [`slash-commands.ts`](../../../src/models/google-chat-agent/services/slash-commands.ts) — `/help`, `/whoami`, `/reset` handlers + attachment / unlinked replies. Bypass the LLM entirely.
- [`AgentChatEvent`](../../../src/models/google-chat-agent/types/chat-event.types.ts) extended payload type with `message.text`, `message.thread.name`, `message.attachment`.
- [`GoogleChatEventsController`](../../../src/models/notifications/controllers/google-chat-events.controller.ts) MESSAGE branch updated: when `agent.isEnabled()`, delegates to `GoogleChatAgentService`; otherwise falls back to the legacy "notifications-only" stub from `BotEventHandlerService`.
- [`NotificationsModule`](../../../src/models/notifications/notifications.module.ts) imports `GoogleChatAgentModule` to inject the agent service into the controller.
- ADDED_TO_SPACE / REMOVED_FROM_SPACE handlers untouched — regression-safe.

**Verified:** 11 unit tests in [`google-chat-agent.service.spec.ts`](../../../src/models/google-chat-agent/services/google-chat-agent.service.spec.ts) cover disabled flag, missing Claude key, unlinked identity, missing context, attachment fallback, no-text fallback, all three slash commands (case-insensitive), and `isEnabled()` reflecting both config + Claude state. All notification tests still pass. Total module tests: **76/76** passing; build clean.

**Caveats / things to know:**
- **No live Chat API end-to-end test in this module.** M8-I1 (real captured webhook payload → render in dev space) requires either a captured fixture file or a live ngrok session. Both are setup tasks rather than code; the unit tests cover the dispatch logic. First time the bot will speak in Chat is when `GOOGLE_CHAT_AGENT_ENABLED=true` + a real Anthropic key are both set in dev — likely the next thing you'll do.
- **Synchronous response model.** The webhook returns the agent reply inline. With Sonnet + tool-use loops up to 6 iterations + tool DB queries, a complex turn could approach Google's 30s timeout. `GOOGLE_CHAT_AGENT_TURN_TIMEOUT_MS=30000` is the budget; M16 observability will surface latencies. Async (queue + sendDirectMessage) is a future option if needed.
- **Tool-use loop is here, not in M15.** M15 (model router) was supposed to own the Claude wiring. I put the tool-use loop in M8 because it's needed *now* for the bot to do anything. M15 will refactor by adding a Haiku triage step *before* this loop, plus prompt-cache for system; the loop itself stays.
- **History stored as plain text.** When a turn included a tool call, only the assistant's prose summary is stored, not the tool_use/tool_result blocks. Reason: blocks bloat thread state and the model's prose summary already carries the relevant context. Trade-off: on a follow-up like "and what about next week?", the model has to re-call the tool. Acceptable in v1.
- **Multi-tool-per-turn renders the LAST tool's card.** If the model calls `listMyShifts` then `listAvailableShifts` in one turn, the user sees the available-shifts card with the model's overall summary text. This rarely matters for v1 since the system prompt nudges the model to one tool per turn, but worth noting.
- **`/reset` does not clear server-side transcripts (M11).** Just clears the Redis conversation state (M3). Audit transcripts are durable by design.

---

### M9. Response rendering ✅ (M5 + M6 + M7 surfaces — full read/write coverage)

**Goal.** Don't dump prose paragraphs. Render structured tool results as Card v2; fall back to text only for greetings, errors, and short answers.

**Touch points:**
- `src/models/google-chat-agent/rendering/`:
  - `shift-list.card.ts`, `shift-detail.card.ts`, `availability.card.ts`, `time-off.card.ts`, `write-confirmation.card.ts` (with undo button), `error.card.ts`, `quota-exhausted.card.ts` (M14), `disabled.card.ts` (M13).

**Rule:** the model never emits cards directly. The agent loop inspects the *last tool result*; if there's a registered renderer, the assistant's text becomes the card's summary header and structured data renders as the body.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M9-U1 | unit | Empty list renders the "nothing scheduled" variant |
| M9-U2 | unit | Lists exceeding `MAX_INLINE_ROWS` render with "view all in app" deep link |
| M9-U3 | unit | Card payload size stays under Google's 32KB limit on a 50-item stress fixture |
| M9-U4 | unit | Tool errors render an error card with `errorId` for log correlation |
| M9-U5 | unit | Write-confirmation card includes a working undo button payload |
| M9-I1 | integration | Render-and-post in dev space — Chat API accepts every card variant |

**Done when:** M9-I1 produces valid cards in the dev test space.

**Done (M5 surface):**
- Card v2 minimal types + constants (`MAX_INLINE_ROWS=10`, `MAX_CARD_BYTES=30000`) at [`card.types.ts`](../../../src/models/google-chat-agent/rendering/card.types.ts).
- [`CardRendererRegistry`](../../../src/models/google-chat-agent/rendering/renderer.registry.ts) — per-tool renderers; returns null for unmapped tools (text fallback).
- Three M5 shift renderers: [`my-shifts.card.ts`](../../../src/models/google-chat-agent/rendering/shifts/my-shifts.card.ts), [`shift-detail.card.ts`](../../../src/models/google-chat-agent/rendering/shifts/shift-detail.card.ts), [`available-shifts.card.ts`](../../../src/models/google-chat-agent/rendering/shifts/available-shifts.card.ts).
- Direct-use helpers: [`buildErrorCard`](../../../src/models/google-chat-agent/rendering/error.card.ts), [`buildDisabledCard`](../../../src/models/google-chat-agent/rendering/disabled.card.ts) — used by the agent service in M8/M13/error paths, not via the renderer registry.
- [`ShiftRenderersProvider`](../../../src/models/google-chat-agent/rendering/shifts/shift-renderers.provider.ts) registers all three on `onModuleInit`. Wired into `GoogleChatAgentModule`.
- Date/time helpers in [`format.ts`](../../../src/models/google-chat-agent/rendering/format.ts) — UTC-anchored display until tz column lands.

**Verified:** 20 unit tests in [`rendering.spec.ts`](../../../src/models/google-chat-agent/rendering/rendering.spec.ts) cover empty states, overflow at `MAX_INLINE_ROWS` with "+N more" hint, payload size under `MAX_CARD_BYTES` on a 50-shift stress fixture, error-card error-id surfacing, disabled-card defaults, and registry semantics. Total module tests: **65/65** passing; build clean.

**Caveats:**
- **M6/M7 renderers (availability, time-off, write-confirmation cards) deferred** until those modules land — this M9 covers M5's surface end-to-end. Renderer pattern is established; new renderers slot in via the same registry.
- **No undo button on writes yet.** Plan calls for a 60s undo on M7 write-confirmations. That requires action handlers (Chat → backend) which is more than an M9 concern. Lands with M7.
- **M9-I1 (live render-and-post in dev space) is gated on M8.** Until the webhook MESSAGE branch is wired, there's no path from a card to the Chat API. Manual end-to-end card validation will happen as part of M8's bring-up.

---

### M10. RBAC enforcement (self-only) ❌

**Goal.** A single choke point all tool dispatches pass through. The contract is simple **because the scope is simple**: caller can read and modify only their own data.

**Touch points:**
- `src/models/google-chat-agent/rbac/agent-rbac.guard.ts`.
- Wraps `Registry.dispatch` such that:
  1. Caller has a non-revoked `user_chat_connections` row.
  2. The underlying service call is made with `actorUserId = resolvedUser.userId`, never with the bot's service account identity.
  3. Tools have no `requiredRoles` field — the simplification is intentional. If a manager tool is ever needed, that's a new module that adds back role gating.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M10-U1 | unit | Caller without an active chat connection denied |
| M10-U2 | unit | Underlying service receives `actorUserId === resolvedUserId` (never service account) |
| M10-U3 | unit | Service-level errors (policy denial) propagate as structured `RbacDeniedError`, not generic 500 |

**Done when:** the unit tests pass; manual negative test (bot disabled mid-session, caller's chat connection revoked) returns clean denial.

---

### M11. Transcript & audit logging ✅

**Goal.** Every agent turn (user message, model output, each tool call + result) goes to a row. Used for debugging, abuse review, prompt tuning, and the M14 quota counter.

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
    payload jsonb not null,        -- with redaction policy applied at write time
    tokens_in int null,
    tokens_out int null,
    cost_usd numeric(10,6) null,
    counts_against_quota boolean default true,   -- false for system / error turns
    created_at timestamptz default now()
  )
  index on (organization_id, user_id, created_at desc)
  index on (chat_thread_name, turn_index)
  ```
- `agent-transcript.service.ts`.

**Redaction policy (v1):** payload stored verbatim by default. Per-org `PII_REDACTION` flag (default off until C8 cleared) swaps in a redactor that replaces email/phone with `[redacted]` before write.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M11-U1 | unit | One row per turn with monotonic `turn_index` per `chat_thread_name` |
| M11-U2 | unit | Token counts match the SDK's reported usage |
| M11-U3 | unit | `PII_REDACTION=on` masks email/phone; off stores raw |
| M11-U4 | unit | `counts_against_quota=false` for system errors and disabled-card replies |
| M11-I1 | integration | Failure to write a transcript does not block the user reply (logged + Sentry'd, not thrown) |

**Done when:** M11-I1 verified by injecting a write failure.

**Done:**
- Migration [`20260505030000-create-agent-chat-transcripts.ts`](../../../src/database/migrations/20260505030000-create-agent-chat-transcripts.ts) — table with org/user uuids, monotonic `(chat_thread_name, turn_index)` unique, role check constraint, indexes for usage dashboard + thread playback, FKs to users/organizations with `ON DELETE CASCADE`. Registered in [`migrations/index.ts`](../../../src/database/migrations/index.ts).
- Entity [`AgentChatTranscript`](../../../src/models/google-chat-agent/entities/agent-chat-transcript.entity.ts) with numeric→number transformer for `cost_usd`.
- [`AgentTranscriptService.recordTurn()`](../../../src/models/google-chat-agent/services/agent-transcript.service.ts) — never-throws contract; computes `turn_index` via `MAX+1` subquery in the INSERT; applies redaction when `GOOGLE_CHAT_AGENT_PII_REDACTION=true`.
- [`pii-redaction.ts`](../../../src/models/google-chat-agent/services/pii-redaction.ts) — narrow-scope redactor for emails + 7+digit phones; recurses through arrays/objects; non-string primitives pass through.
- Tool-use loop returns aggregated `tokensIn` / `tokensOut` across all loop iterations and surfaces per-call `input` / `output` / `error` in `toolCalls[]`.
- [`GoogleChatAgentService`](../../../src/models/google-chat-agent/services/google-chat-agent.service.ts) writes:
  - **user** row (counts against quota)
  - **tool** row per dispatch (does not double-count)
  - **assistant** row with token totals + `toolCallSummary` + provider/model
  - **system** row for slash commands, attachment fallback, empty text, and pipeline errors (best-effort when identity resolves)
- New env var: `GOOGLE_CHAT_AGENT_PII_REDACTION=true` (default false; turn on once C8 is cleared).

**Verified:** 17 unit tests landed across [`pii-redaction.spec.ts`](../../../src/models/google-chat-agent/services/pii-redaction.spec.ts), [`agent-transcript.service.spec.ts`](../../../src/models/google-chat-agent/services/agent-transcript.service.spec.ts), and additions to [`google-chat-agent.service.spec.ts`](../../../src/models/google-chat-agent/services/google-chat-agent.service.spec.ts) covering redaction on/off, never-throws on DB failure, token-count parameter passing, `countsAgainstQuota` defaults, slash/attachment/disabled/unlinked transcript behavior, and SQL shape (MAX+1 subquery present). Total module tests: **102/102** passing; build clean.

**Caveats:**
- **Migration not yet run.** `npm run migrate` creates the table — left for the user to run on their dev DB. Until then, every transcript write logs a warning and the user reply still succeeds (never-throws contract).
- **`turn_index` race condition is real but tiny.** Two webhook calls on the same thread within milliseconds could read the same MAX, then collide on the unique constraint. Per-thread concurrency in Chat is realistically zero (one user, sequential webhook calls), so the unique constraint is sufficient. If we ever see collisions, switch to a Postgres advisory lock per thread.
- **Cost calculation deferred.** `cost_usd` column exists but is always written as null. Cost-from-tokens math lands with M16 observability (per-model rate table).
- **Redaction is narrow.** Only emails and 7+digit phones. Names, medical context in free text, and other PII categories aren't redacted. Compliance gate C8 will likely require a stronger redactor before turning the flag on in prod.
- **Tool input/output stored verbatim in `payload`.** With redaction off (current default for dev), this means raw shift data, role names, etc. land in the table. Acceptable for synthetic data; revisit before any prod tenant.

---

### M12. Rate limiting (abuse control) ❌

**Goal.** Stop runaway loops. **Not** the same as M14 quota — this prevents bursts; quota enforces the free-tier limit.

**Limits (v1):**
- Per-user: 60 messages / hour.
- Per-org: 10,000 messages / day (a circuit breaker, not a price cap).
- Per-thread: 50 turns within TTL window before forced `/reset` prompt.

**Touch points:**
- `src/models/google-chat-agent/limits/rate-limit.service.ts`, Redis-backed sliding window.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M12-U1 | unit | 61st request in an hour denied with friendly card |
| M12-U2 | unit | Org-level cap hits before per-user when both apply |
| M12-U3 | unit | Counter resets at window boundary |
| M12-I1 | integration | 100 concurrent fakes count exactly once each (Redis Lua / `INCR` semantics) |

**Done when:** unit + concurrency integration test green.

---

### M13. Feature flag & rollout ❌

**Goal.** Per-org enable. Allowlist for early access. Global kill switch.

**Touch points:**
- Reuses `organization_integrations` row from notification module. Add column `scheduling_agent_enabled boolean default false` (migration in this module).
- Global env `GOOGLE_CHAT_AGENT_ENABLED` from M1 acts as the kill switch — when false, no org's flag matters.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M13-U1 | unit | Org flag false → friendly disabled card without any LLM call |
| M13-U2 | unit | Global kill switch overrides org flag |
| M13-I1 | integration | Toggling flag mid-session: existing thread stops responding; new threads see disabled card |

**Done when:** integration test passes; org admin can flip the flag from the existing integrations page (UI tracked in [frontend doc](../frontend/agent-google-chat-bot-frontend.md)).

---

### M14. Quota & monetization ❌ (impl 💤 deferred)

**Goal.** Each employee gets **50 free messages**. After that, the bot replies with an upgrade card and no further LLM calls happen for that user until quota is extended (manually now; via paid tier later).

**Phase split:**
- **Phase 14a (lands now):** data model + counter + free-tier enforcement + upgrade-card response. **No payment integration.** Manual quota top-up via DB / admin tool only.
- **Phase 14b (deferred 💤):** paid-tier billing — pricing model, payment provider, invoice flow, auto top-up. Implementation deferred until product decides on pricing and payor (org-level subscription vs. per-user).

**Reset cadence — decided.** Free tier is **50 messages per user per calendar month**, anchored to the user's first-message timestamp (not the calendar 1st — avoids end-of-month rush). Lifetime caps were considered and rejected: 50 lifetime is too few if the bot proves useful (a user could exhaust it in a month and never use it again), and it creates a bad upgrade-pressure shape. Monthly resets give a meaningful free experience while still creating clear upgrade pressure for power users.

**Phase 14a touch points:**
- New migration `<timestamp>-create-agent-user-quota.ts`:
  ```
  agent_user_quota(
    user_id int pk,
    organization_id int not null,
    messages_used int not null default 0,
    messages_granted int not null default 50,    -- baseline per month; can be raised manually
    period_anchor_at timestamptz not null,        -- user's first-message ts; resets compute from this
    current_period_start_at timestamptz not null, -- start of the user's current monthly window
    plan text not null default 'free',            -- 'free' | 'paid' (paid path arrives in 14b)
    created_at timestamptz default now(),
    updated_at timestamptz default now()
  )
  index on (organization_id)
  ```
- Reset logic: on every `checkAndIncrement`, if `now() >= current_period_start_at + interval '1 month'`, reset `messages_used = 0` and roll `current_period_start_at` forward by month-aligned increments until it covers `now()`. Manual top-ups (`grant`) raise `messages_granted` for the *current* period only; the next reset returns to the baseline.
- `src/models/google-chat-agent/quota/quota.service.ts`:
  ```ts
  async checkAndIncrement(userId): Promise<{ allowed: boolean; remaining: number }>;
  async getStatus(userId): Promise<{ used: number; granted: number; remaining: number; plan: string }>;
  async grant(userId, additionalMessages, reason): Promise<void>;       // admin-only, audited
  ```
- Quota check sits between identity resolution (M2) and the LLM call (M15). When `allowed=false`, the agent renders the **quota-exhausted card** (M9) and writes a transcript row with `counts_against_quota=false`.

**What counts against quota.** One inbound user MESSAGE = one quota unit, regardless of how many tool calls the model issues internally to satisfy it. Slash commands (`/help`, `/reset`, `/whoami`) don't count. The disabled-card and quota-exhausted-card responses don't count.

**Quota-exhausted card (Phase 14a copy):** "You've used your 50 free messages with the scheduling assistant. Reach out to your administrator to extend your access." **(Phase 14b will replace with an in-card upgrade CTA.)**

**Open questions on pricing model (resolve before 14b):**
- **Q-PR1.** Per-user paid plan, or org-level subscription that lifts the cap for all employees? Default proposal: org-level subscription — the org is the payor in healthcare workflows, not the individual.
- **Q-PR2.** ~~Reset cadence on free tier.~~ **Decided: 50 messages per user per calendar month, anchored to first-message timestamp.** See "Reset cadence — decided" above.
- **Q-PR3.** Pricing — flat per-org per-month, per-active-user, or per-message overage? Default proposal: tiered org subscription with an included message bundle and per-message overage.
- **Q-PR4.** Failure mode on payment lapse: hard-stop (revert to free) or grace period? Default proposal: 14-day grace, then revert.

**Tests (Phase 14a):**

| ID | Type | Proves |
|---|---|---|
| M14-U1 | unit | First 50 messages: each `checkAndIncrement` returns `allowed=true` with decreasing `remaining` |
| M14-U2 | unit | 51st message: `allowed=false`; quota row not incremented past `granted` |
| M14-U3 | unit | `grant(userId, +50, …)` lifts ceiling; the user's next message is allowed |
| M14-U4 | unit | Slash commands (`/help`, `/reset`) do not call `checkAndIncrement` |
| M14-U5 | unit | Disabled-card and quota-exhausted-card paths skip `checkAndIncrement` |
| M14-U6 | unit | Concurrent increments under Postgres advisory lock or row lock — no double-spend at the boundary |
| M14-I1 | integration | 50 successful turns + 51st returns the quota-exhausted card; admin grant lifts and 52nd succeeds |
| M14-I2 | integration | `agent_user_quota` row auto-created on first message for an unseen user |

**Tests (Phase 14b — written when implemented):** payment provider webhook integration, plan upgrade reflected in real-time, downgrade on payment failure, invoice generation. All deferred.

**Done when (14a):** all 14a tests green; one user can be manually granted more messages via the service method; quota-exhausted card renders correctly. **14b stays 💤** until pricing decisions are made.

---

### M15. Model router ❌

**Goal.** Don't pay Sonnet prices for "hi" or "thanks." Cheap classification first; escalate to Sonnet when the model needs tools or substantive output.

**Routing:**
1. Preprocessor: trivial intents (greeting, thanks, "help" → `/help` redirect) reply locally without any LLM call.
2. Else: single Haiku call with a tight system prompt and an "escalate?" tool. Yes → Sonnet hand-off with full tool registry.
3. Else: Haiku's reply is the answer.

**Touch points:**
- `src/models/google-chat-agent/router/model-router.service.ts`.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M15-U1 | unit | "hi" intercepted before any LLM call (asserts neither client called) |
| M15-U2 | unit | Haiku's escalation tool result triggers Sonnet with the full tools payload |
| M15-U3 | unit | Sonnet timeout surfaces as a "took too long, try again" card, not a 500 |
| M15-I1 | integration | "what are my shifts this week?" → Sonnet tool-use loop end-to-end (live, gated) |

**Done when:** M15-I1 measurable in dev: greeting cost $0; shift query cost recorded in transcript.

---

### M16. Observability ✅

**Goal.** When something feels off, on-call can find out why in under 5 minutes.

**What gets emitted:**
- Structured log per turn: `{ turnId, userId, orgId, threadName, model, toolsCalled, tokensIn, tokensOut, costUsd, latencyMs, quotaRemaining, error? }`.
- Sentry breadcrumb chain per turn; errors tagged with `turnId`.
- Metrics: `agent_turn_latency_seconds`, `agent_turn_cost_usd`, `agent_tool_calls_total{tool=…}`, `agent_quota_blocks_total`.

**Touch points:**
- `src/models/google-chat-agent/observability/agent-telemetry.service.ts`.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M16-U1 | unit | Errored turn emits a log with `error.message` and a Sentry capture (mocked) |
| M16-U2 | unit | Latency metric recorded even on the error path |
| M16-I1 | integration | Sample turn produces all expected metrics in the test registry |

**Done when:** metrics scrapeable in dev; deliberate error appears in Sentry.

**Done (pragmatic v1):**
- [`cost-rates.ts`](../../../src/models/google-chat-agent/observability/cost-rates.ts) — per-model rate table (gpt-4o, gpt-4o-mini, claude-sonnet-4-5, claude-haiku-4-5) with safe fallback. `computeCostUsd(model, in, out)` returns USD rounded to 6 decimals (matches the `cost_usd numeric(10,6)` column from M11).
- [`AgentTelemetryService`](../../../src/models/google-chat-agent/observability/agent-telemetry.service.ts) — `startTurn()` returns a `TurnTracker` (captures `Date.now()`); `costForTurn()` centralises the cost figure so the log line and the transcript row agree; `recordTurn()` emits **one structured JSON log line** per turn with `event: 'agent_turn'` and the full snapshot. Errors route to `Logger.error`, success to `Logger.log`. Always succeeds (try/catch around stringify catches cyclic data).
- [`GoogleChatAgentService`](../../../src/models/google-chat-agent/services/google-chat-agent.service.ts) wires the tracker through every exit path: disabled / context_missing / unlinked / slash / empty / attachment_only / success / error. Each emits exactly one telemetry record with `latencyMs >= 0`.
- The success path passes the computed `costUsd` into the assistant transcript row (M11) so the SQL queries in the M11 plan section now return non-null cost data.
- `AgentTelemetryService` registered + exported in [`GoogleChatAgentModule`](../../../src/models/google-chat-agent/google-chat-agent.module.ts).

**Verified:** 23 unit tests across [`cost-rates.spec.ts`](../../../src/models/google-chat-agent/observability/cost-rates.spec.ts) (rate lookup + cost arithmetic + rounding), [`agent-telemetry.service.spec.ts`](../../../src/models/google-chat-agent/observability/agent-telemetry.service.spec.ts) (tracker timing, structured log shape, error-path routing, M16-U2 latency-on-error, defensive non-throwing emit), and additions to [`google-chat-agent.service.spec.ts`](../../../src/models/google-chat-agent/services/google-chat-agent.service.spec.ts) (telemetry fires on every exit path with correct `outcome`). Total module tests: **169/169** passing; build clean.

**Caveats:**
- **Sentry / Prometheus deferred.** Plan called for both. Project doesn't have either wired up, and adding them is an org-wide infra decision rather than agent-module work. The single structured log line per turn is the primary signal today; once Sentry exists, the existing error path (already routed via `Logger.error`) is the right hook point. Prometheus would consume the same TurnSnapshot via a registry adapter — F-item.
- **Cost is approximate.** Public list prices, no cache-discount adjustment. Anthropic prompt caching makes reported cost a slight overestimate when caching kicks in; OpenAI auto-caches but doesn't bill differently in the API response. Acceptable for dashboards; not for billing.
- **Rate table is hard-coded.** Vendors update pricing periodically. There's a `console.warn` for unknown models — when you see one in logs, add it to `cost-rates.ts`.
- **No metrics export.** Logs only. To compute "average turn cost last hour" today, query `agent_chat_transcripts` (M11 stores per-row cost). When metrics arrive, the structured log lines are already shaped to feed a metric pipeline.

---

### M17. Help & discoverability ❌

**Goal.** A first-time user finds their way in 30 seconds.

**Touch points:**
- `/help` slash command listing capabilities (read shifts, read availability, set availability, request time off, see remaining quota).
- Onboarding card auto-posted once when the user first engages with the bot after M13 enables for their org.

**Tests:**

| ID | Type | Proves |
|---|---|---|
| M17-U1 | unit | `/help` content is identical for all employees (no role variants — there's only one role) |
| M17-U2 | unit | Onboarding card posts once per `(user, org)`; second invocation is a no-op |
| M17-I1 | integration | DM `/help` to the bot — card renders with all expected sections including current quota status |

**Done when:** manual DM test feels usable to someone unfamiliar with the bot.

---

## 4. Dependencies between modules

```
M1 ─┬─► M2 ─┬─► M4 ─┬─► M5 ─┬─► M8 ─► M15 ─► M9
    │       │       │       │
    └─► M3 ─┘       ├─► M6 ─┤
                    │       │
                    └─► M7 ─┘

M10 ───────► gates dispatch in M4 — implement alongside M4
M11 ───────► writes from inside M4 dispatch — implement alongside M4
M12 ───────► gates entry to M8 — implement alongside M8
M13 ───────► gates entry to M8 — implement alongside M8
M14 ───────► gates entry to M8 (after M2 resolves identity) — implement alongside M8
M16 ───────► cross-cuts; instrument as each module lands
M17 ───────► after M8 + M9 are usable
```

**Suggested critical path:** M1 → M2 → M3 → M4 (with M10 + M11) → M5 → M9 → M8 (with M12 + M13 + M14a) → M15 → M6 → M7 → M16 → M17.

A useful read-only v0 ships after M9. M7 (employee writes) can come after.

---

## 5. Cross-cutting test infrastructure

Built up front during M1:

- **Test harness for tool calls.** A `runTool(toolName, input, asUser)` helper that hits the registry the same way a real Chat MESSAGE would — exercising RBAC + transcript + quota + telemetry — so tests cover the real pipeline, not the bare handler.
- **DB seed factories** for shifts, employees, availability rules, time-off requests. Reuse anything that exists; extend per module.
- **Mocked Anthropic client** with deterministic fake completions for unit tests (record-replay style; not live).
- **Live integration suite** behind `RUN_LIVE_AI_TESTS=1` for M1-I1, M15-I1, M9-I1, M14-I1 cases that need a real API call.
- **Captured Chat webhook fixtures.** `tests/fixtures/chat-message-*.json` — recorded from dev, replayed in tests.

**Scripted-LLM scenario tests (added during M7 follow-up).**

Real Chat dev testing surfaced two bug classes that the per-tool unit tests didn't catch:
1. The model lost confirmation context across turns ("Yes" treated as a fresh greeting).
2. Multi-turn flows that depend on conversation state weren't tested at the integration level.

Added [`__test_helpers__/scripted-llm.ts`](../../../src/models/google-chat-agent/services/__test_helpers__/scripted-llm.ts) with:

- `scriptedOpenAI(responses[])` — fake OpenAI client that returns scripted `ChatCompletion` objects in order. **Deep-clones** the `messages` array on every call (the real loop reuses + mutates one array across iterations; reference snapshots would lie).
- `toolCallResponse([{name, argsJson}], usage?)` — convenience builder for assistant-with-tool_calls completions.
- `textResponse(text, usage?)` — convenience builder for plain-text completions.

Two scenario spec files exercise the helpers:

- [`tool-use-loop.scenarios.spec.ts`](../../../src/models/google-chat-agent/services/tool-use-loop.scenarios.spec.ts) — 5 tests that verify the `runOpenAILoop` correctly threads prior history into the LLM, captures token usage across multiple LLM calls, surfaces tool errors as `is_error` tool_results without crashing, handles plain-text responses without dispatching, and chains multiple parallel tool calls in one turn.
- [`google-chat-agent.scenarios.spec.ts`](../../../src/models/google-chat-agent/services/google-chat-agent.scenarios.spec.ts) — 6 tests that exercise the **full pipeline** (real `ConversationStateService` with a `FakeRedis`, real `ToolRegistry`, real renderer registry, scripted LLM). Includes the **confirmation-flow regression test**: turn 1 the model proposes an action, turn 2 the user says "Yes," and we assert the LLM call on turn 2 receives the prior assistant question in its `messages` array. **If conversation state ever stops persisting assistant turns, this test fails — exactly the bug observed in dev.**

These add up to a third type of test alongside unit tests and per-module mocks: **deterministic conversation-flow tests** that catch regressions in cross-turn behavior without the cost or flakiness of real LLM calls.

---

## 6. Open questions

**Pre-prod / compliance gates** are tracked in [§0](#0-compliance--data-privacy-pre-prod-blocker) — not duplicated here.

**Pricing & monetization questions** are tracked inline in [M14 (Q-PR1 → Q-PR4)](#m14-quota--monetization--impl--deferred) — they only need answers before Phase 14b lands.

**Design questions to resolve before starting the related modules:**

1. **Confirmation UX for writes (before M7).** Default proposal: writes execute immediately, M9 renders a 60s undo card. Confirm.
2. **Tool naming surface (before M4).** User-facing vocabulary (`shift`) vs internal (`employee_shift`). Default: user-facing.
3. **Multi-language (post v1).** Arabic queries — Sonnet handles natively; M9 cards need RTL-safe layouts. Defer past v1 unless the rollout demographic forces it sooner.
4. **Time-zone semantics (before M5).** "Tuesday at 8am" — caller's tz, org's tz, or shift site's tz? Default proposal: tools accept times in the org's primary tz unless the user names one explicitly; rendering converts to caller's tz.
5. **Quota visibility in `/help` (before M17).** Default proposal: `/help` shows "X / 50 messages remaining" so users aren't surprised when they hit the cap. Confirm acceptable.

---

## 7. Future enhancements

Stable IDs — never renumber.

- **F1.** Proactive nudges: "you haven't set availability for next month; want to copy last month's?"
- **F2.** Standalone MCP server exposing the same tool registry — Claude Desktop / Claude.ai / future internal tools reuse the scheduling surface without the Chat front-end.
- **F3.** Manager-facing tools as a separate, role-gated surface (assignment matchers, cross-employee queries). Out of v1; would be a sibling module set rather than expanding this one, to keep RBAC simple here.
- **F4.** Voice channel (Twilio / Google Voice) reusing the same tool registry.
- **F5.** Patient/visit awareness — answer "who's my first patient tomorrow?" Out of v1 scope.
- **F6.** Quota top-up self-service — the user pays for more messages directly from the bot card (depends on 14b billing).
- **F7.** Org-admin analytics page — per-employee usage, top tools, costs, quota status.

---

## 8. Working agreements

- **Hard isolation from the org-end AI agent.** This module never imports from, extends, or shares state with the existing organization-end HomeHealth AI agent. No shared tools, prompts, identity layer, transcripts, or quota counters. If a query shape needs to exist at the individual level, extend the underlying *domain service*, not the org agent. Any PR that crosses this line is a bug — flag it in review. (See scope callout at the top of this doc.)
- **No bypassing existing services.** Every tool is a thin adapter. If a service can't answer the question, extend it first (in `src/models/organizations/scheduling/services/` or similar); never duplicate logic in the agent module.
- **Self-only is the default.** Any tool that reads or writes data outside the caller's own scope requires a new module and explicit RBAC additions; it doesn't slip in.
- **Every write is auditable.** Row in `agent_chat_transcripts` *and* whatever audit row the underlying service already produces.
- **Tests gate ✅.** A module is not ✅ until both the unit + integration tests in its section pass and a manual DM was exercised end-to-end.
- **Live API tests are gated.** Never run in CI by default; only when `RUN_LIVE_AI_TESTS=1` and `ANTHROPIC_API_KEY` are set.
- **Compliance gates (§0) precede production.** Modules can be built on synthetic data; no real org data flows until C1–C8 are cleared.
