# Google Chat Integration — Execution Plan

Module-by-module status tracker. Edit in place as work progresses; don't append changelog entries. For architecture, decisions, schemas, and UI mockups, see [integration-google-chat.md](integration-google-chat.md) — this file is execution-only.

## Status legend

- ✅ Complete and verified
- 🚧 In progress
- ❌ Not started
- 💤 Deferred (post-MVP / future)

## Quick status

| # | Module | Status | One-line state |
|---|---|---|---|
| 1 | Google Cloud — dev project | ✅ | App configured, service account created, OAuth consent done |
| 2 | Google Cloud — prod project | ❌ | Needs creation under HomeHealth Workspace tenant |
| 3 | Webhook stub controller | ✅ | Round-trip tested via ngrok; bot replies on ADDED_TO_SPACE / MESSAGE |
| 4 | Webhook signature verification | ✅ | JWT verification active; dev escape hatch via `GOOGLE_CHAT_VERIFY_SIGNATURE=false` |
| 5 | Data layer — migrations & entities | ✅ | Three tables created on dev DB; entities + module wiring done |
| 6 | Real bot event handlers (DB linking) | ✅ | ADDED creates connection row; REMOVED flips status to revoked; verified end-to-end |
| 7 | Chat API client + service account wiring | ✅ | Service account JSON loaded; authenticated `chat_v1.Chat` client live; startup smoke-test passes |
| 8 | Google Chat channel adapter | ✅ | `sendDirectMessage` lands in user's Chat inbox; verified by curl-triggered test DM |
| 9 | Email channel adapter | ✅ | Generic `EmailChannelService.send(to, subject, html)`; verified by test email landing in inbox |
| 10 | Dispatcher service | ✅ | Channel routing, render, send, idempotency, log — all 3 paths verified |
| 11 | Document expiry scanner (cron) | ✅ | Daily 8am UTC scan; v1 walks `inservice_completions`; dispatched a 7d reminder end-to-end |
| 12 | BullMQ producer + consumer | ✅ | Scanner → `reminder-dispatch` queue → consumer → dispatcher; rate-limited; jobId-dedupe |
| 13 | Org admin API endpoints | ✅ | 6 endpoints under `/v1/api/organizations/:orgId/integrations/google-chat`; all verified with real JWT |
| 14 | Org admin UI — setup wizard | ❌ | 3-step: domain → install → cadence |
| 15 | Org admin UI — manage page | ❌ | Status + cadence + employee list |
| 16 | Employee API endpoints | ✅ | 3 endpoints under `/v1/api/me/notifications`; verified incl. personal-Gmail rejection |
| 17 | Employee UI — notifications settings | ❌ | States 1–4 from design doc |
| 18 | Marketplace publication | ❌ | Long pole; weeks of Google review |
| 19 | Local dev infrastructure | 🚧 | ngrok working; static domain not yet reserved |

## Modules

### 1. Google Cloud — dev project ✅

**Done:**
- `homehealth-reminders-dev` GCP project created (currently under Guardian's Workspace tenant for dev iteration).
- Google Chat API enabled.
- Chat app configured: name "HomeHealth Reminders," "Build as Workspace add-on" unchecked, interactive features on, common HTTP endpoint URL trigger, visibility allowlist for `developer2@guardianhha.com`, error logging enabled, authentication audience = HTTP endpoint URL.
- Service account `homehealth-chat-bot` created; JSON key downloaded (not yet wired into backend secrets — see module 7).
- OAuth consent screen configured (minimal — no user OAuth scopes for bot-auth).

**Verified:** the bot is discoverable in `developer2@guardianhha.com`'s Google Chat (search "HomeHealth Reminders" in New chat → bot appears). Adding the bot triggers `ADDED_TO_SPACE` POST to the configured webhook URL. Configuration is correct.

**Remaining:** none for dev. Webhook URL gets updated per session as ngrok rotates (will be permanent once a static ngrok domain is reserved in module 19).

### 2. Google Cloud — prod project ❌

**Why separate:** the dev project lives under Guardian's Workspace tenant. Prod must be hosted under HomeHealth's own Workspace (e.g. `homehealth.ai`), because the project's home org determines Marketplace ownership.

**Remaining:**
- Create `homehealth-reminders-prod` GCP project under HomeHealth's Workspace.
- Mirror the dev app config (name, avatar, description, endpoint, audience, scopes).
- Don't enable Chat API or submit Marketplace until module 18 is ready to ship.

### 3. Webhook stub controller ✅

**Done:**
- [google-chat-events.controller.ts](../../../src/models/notifications/controllers/google-chat-events.controller.ts) — GET (health) + POST (event handler) at `/webhooks/google-chat/events`. Logs every event body. Returns hardcoded welcome on `ADDED_TO_SPACE`, fixed reply on `MESSAGE`, empty `{}` otherwise.
- [notifications.module.ts](../../../src/models/notifications/notifications.module.ts) — registers controller.
- Imported into [app.module.ts](../../../src/app.module.ts).

**Verified:** sent `Hi` from `developer2@guardianhha.com`'s Chat → bot replied with the hardcoded welcome message → NestJS terminal logged the full event payload at DEBUG. Round-trip confirmed.

**Remaining:** none at the stub level. Real handler logic moves to module 6.

### 4. Webhook signature verification ✅

**Done:**
- [google-chat-request.guard.ts](../../../src/models/notifications/guards/google-chat-request.guard.ts) — verifies `Authorization: Bearer <jwt>` against Google's OIDC certs fetched from `https://www.googleapis.com/oauth2/v1/certs` (1-hour cached). Checks RS256 signature + `iss = https://accounts.google.com` + `payload.email = chat@system.gserviceaccount.com` + optionally `aud`.
- Config module [src/config/google-chat/](../../../src/config/google-chat/) (`configuration.ts`, `config.module.ts`, `config.service.ts`) — exposes `verifySignature`, `audience`, `issuer`, `serviceAccountJson` from env.
- `@UseGuards(GoogleChatRequestGuard)` applied to `POST /webhooks/google-chat/events`. GET `/events` health check is unguarded.
- Env vars added to `.env`: `GOOGLE_CHAT_VERIFY_SIGNATURE`, `GOOGLE_CHAT_AUDIENCE`, `GOOGLE_CHAT_ISSUER`, `GOOGLE_CHAT_SERVICE_ACCOUNT_JSON` (last one wired in module 7).
- `google-auth-library` installed (will also be used by the Chat API client in module 8).

**Verified:**
- Negative: `curl POST` without bearer → 401 "Missing or malformed bearer token"; with garbage bearer → 401 "Invalid token: no kid in header".
- Positive: real Chat event from `developer2@guardianhha.com` → JWT signature, `iss`, `email` all check out → controller runs → bot replies. Confirmed via NestJS logs (no JWT failure warning) and ngrok inspector (200 response).

**Important nuance discovered during verification:** Google's docs say "JWT iss is `chat@system.gserviceaccount.com`" — that's actually the `email` claim, not `iss`. The real `iss` is `https://accounts.google.com` (Google's standard OIDC issuer used for all Google tokens). The signing keys are Google's general OIDC keys at `oauth2/v1/certs`, not the chat service account's individual certs. Our guard reflects this empirical reality. If Google ever shifts to signing Chat events with the chat service account's own keys, the cert URL in the guard's `getCerts()` will need to change.

**Dev escape hatch:** set `GOOGLE_CHAT_VERIFY_SIGNATURE=false` in `.env` to allow curl/manual testing without crafting real Google JWTs. Logs a warning on every request when disabled. Must be `true` in prod. `.env` changes don't hot-reload — restart `npm run start:dev` after flipping the flag.

**Audience matching:** if `GOOGLE_CHAT_AUDIENCE` is set, the JWT `aud` claim must match. With audience type set to "HTTP endpoint URL" in Google Console, the JWT's `aud` is the full webhook URL (so updating ngrok rotates the audience too). Leave the env var empty during dev to skip audience check while still verifying signature + issuer + email — this is the recommended setup until a static webhook URL is in place.

### 5. Data layer — migrations & entities ✅

**Done:**
- [20260501200000-create-organization-integrations.ts](../../../src/database/migrations/20260501200000-create-organization-integrations.ts) — table + FKs to `organizations`/`users` (ON DELETE CASCADE / SET NULL) + unique `(org_id, provider)` + check on `status` enum + indexes on `org_id` and `status`.
- [20260501200001-create-user-chat-connections.ts](../../../src/database/migrations/20260501200001-create-user-chat-connections.ts) — table + FKs to `users`/`organizations` (CASCADE) + unique `(user_id, provider)` + check on `status` + indexes on `user_id`, `org_id`, `status`.
- [20260501200002-create-notification-dispatch-log.ts](../../../src/database/migrations/20260501200002-create-notification-dispatch-log.ts) — table + FKs to `users`/`organizations` (CASCADE) + unique `(user_id, document_id, reminder_kind, channel)` for idempotency + check on `channel`/`status` + indexes on `user_id`, `org_id`, `sent_at`. `document_id` is intentionally not FK-constrained (polymorphic — `document_type` indicates which table).
- Migrations registered in [src/database/migrations/index.ts](../../../src/database/migrations/index.ts) and applied on dev DB; schema verified via `\d` in psql.
- TypeORM entities at [src/models/notifications/entities/](../../../src/models/notifications/entities/) with proper types, `@Unique`, `@Index` decorators matching the migration constraints. Each entity exports its enum-like string union types (`IntegrationStatus`, `ChatConnectionStatus`, `NotificationChannel`, `ReminderKind`, etc.) for use by future services.
- [NotificationsModule](../../../src/models/notifications/notifications.module.ts) imports `TypeOrmModule.forFeature([...])` for all three entities and exports `TypeOrmModule` so other modules can inject the repositories without re-importing.

**Verified:** ran `npm run migrate` → "No migrations are pending" (dev server's `DB_MIGRATIONS_RUN=true` had already applied them on hot-reload). `psql \d` against `home_health_ai` confirmed all three tables exist with correct columns, FKs (CASCADE / SET NULL), unique constraints, check constraints, and indexes.

- 💤 `notification_preferences` table — deferred to v2.

### 6. Real bot event handlers (DB linking) ✅

**Done:**
- [bot-event-handler.service.ts](../../../src/models/notifications/services/bot-event-handler.service.ts) — encapsulates `handleAddedToSpace`, `handleRemovedFromSpace`, `handleMessage`. Injects `User`, `OrganizationStaff`, `OrganizationIntegration`, `UserChatConnection` repositories.
- `ADDED_TO_SPACE` flow: lookup `users.email` → find `organization_staff` rows where `status='ACTIVE'` → join against `organization_integrations` where `provider='google_chat' AND status='active'` → check email-domain match against `workspace_domain` to set `chat_eligible` → upsert `user_chat_connections` (status `connected`, captures `chat_user_id` and `dm_space_name` from event) → reply with personalized welcome (or compliance-friendly fallback message if `chat_eligible=false`).
- `REMOVED_FROM_SPACE` flow: lookup connection by `(user_id, provider)` → flip status to `revoked` and set `revoked_at`. No-ops gracefully if connection doesn't exist.
- `MESSAGE` flow: returns the existing notifications-only message (unchanged from stub).
- Edge cases handled: user not in HH (replies with helpful message), user not staffed at any org (replies), user's org has no active integration (replies), personal-Gmail / domain mismatch (creates connection with `chat_eligible=false` and replies with email-fallback message).
- Cross-tenant employees (multiple active integrations for one user) — picks the first by org_id and logs a warning. See design doc open question #4 for future resolution.
- **Membership resolution updated** to the three-signal union (owner + staff + employee) per architectural decision #8. Originally checked only `organization_staff` and incorrectly told regular employees + org owners "your account isn't currently active in any organization." Mirrors the same logic in `EmployeeNotificationsService.findUsersOrgIntegration` so the bot-add path and the GET-state path agree.
- [Controller](../../../src/models/notifications/controllers/google-chat-events.controller.ts) updated to delegate to the service. [Module](../../../src/models/notifications/notifications.module.ts) imports `User` and `OrganizationStaff` entities via `TypeOrmModule.forFeature` so the service can inject their repositories.

**Verified:**
- Seeded test data: user `developer2@guardianhha.com`, Guardian org, `organization_staff` row (status ACTIVE, role HR), `organization_integrations` row (provider `google_chat`, status `active`, workspace_domain `guardianhha.com`).
- Removed and re-added the bot in `developer2@guardianhha.com`'s Chat → bot replied *"Hi Web Developer Full Stack, you're connected to HomeHealth Reminders. I'll DM you about expiring documents."* → `user_chat_connections` row created with `status='connected'`, `chat_eligible=true`, correct `chat_user_id` and `dm_space_name` from the event payload.
- Removed the bot a second time → log line `Connection revoked for user e389629f-… (developer2@guardianhha.com)` → DB row flipped to `status='revoked'` with `revoked_at` populated; `connected_at` preserved for audit.
- The earlier `REMOVED_FROM_SPACE` (before any connection existed) silently no-op'd as designed.

### 7. Chat API client + service account wiring ✅

**Done:**
- [google-chat-client.service.ts](../../../src/models/notifications/services/google-chat-client.service.ts) — `OnModuleInit` hook reads the service account JSON, builds a `JWT` from `google-auth-library` with scope `chat.bot`, and constructs an authenticated `chat_v1.Chat` client. Logs initialization with the service account email.
- Service supports two ways to provide the key in `GOOGLE_CHAT_SERVICE_ACCOUNT_JSON`:
  - **Path** (e.g. `secrets/google-chat-service-account.json`) — resolved relative to `process.cwd()`. Used in dev.
  - **Raw JSON** (starts with `{`) — for envs where filesystem isn't available (some PaaS).
- Service account JSON file lives at `secrets/google-chat-service-account.json` (gitignored via the new `secrets/` and `*.serviceaccount.json` patterns in `.gitignore`).
- `@googleapis/chat` installed instead of the meta-package `googleapis`. The full `googleapis` package was tried first but caused TypeScript OOM on `npm run start:dev` (`FATAL ERROR: Ineffective mark-compacts near heap limit`) because it pulls type definitions for every Google API. `@googleapis/chat` is the per-API package — drop-in API (`import { chat, chat_v1 } from '@googleapis/chat'`) with a much smaller type surface.
- Startup smoke-test: after init, the service calls `spaces.list({ pageSize: 1 })` and logs the result. Failure is logged as a warning but doesn't crash the app (graceful degradation if Google's API is temporarily unreachable).
- Service registered as a provider in [notifications.module.ts](../../../src/models/notifications/notifications.module.ts) and exported so module 8 (channel adapter) can inject it.

**Verified:**
- Dev server startup logs show:
  - `Google Chat API client initialized as homehealth-chat-bot@homehealth-reminders-dev.iam.gserviceaccount.com` (JSON parsed, service account email correct).
  - `Chat API smoke-test OK — bot is reachable (0 spaces visible on first page)` (real `spaces.list()` call against Google API succeeded with valid auth).
- 0 spaces is expected because the bot was removed from `developer2@guardianhha.com`'s DM during module 6 testing. Once re-added during module 8 verification, that count will be 1.

### 8. Google Chat channel adapter ✅

**Done:**
- [google-chat-channel.service.ts](../../../src/models/notifications/services/channels/google-chat-channel.service.ts) — thin adapter wrapping the `GoogleChatClientService`. Two methods: `sendDirectMessage(dmSpaceName, text)` calls `client.spaces.messages.create(...)` (used by the dispatcher to deliver reminders), and `leaveSpace(dmSpaceName)` calls `client.spaces.members.delete({ name: <space>/members/app })` to remove the bot from a user's Chat (used by employee disconnect). The latter is **gated by Google to fail on DM spaces pre-Marketplace** with "DMs are not supported for methods requiring app authentication with administrator approval" — see module 16 for the failure mode. Both methods require `chat.bot` scope; `leaveSpace` additionally requires `chat.memberships.app` (now requested in `GoogleChatClientService`'s JWT scopes).
- [google-chat-dev.controller.ts](../../../src/models/notifications/controllers/google-chat-dev.controller.ts) — dev-only `POST /dev/google-chat/test-dm` endpoint that takes `{email, text}`, looks up the user's connection, and triggers `sendDirectMessage`. Returns 404 in prod (`NODE_ENV === 'production'`) so it can't accidentally be used in a deployed environment.
- Module wires up the channel as both a provider and an export so module 10 (dispatcher) and any future code can inject it.
- 💤 Cards v2 with action buttons (Upload now / View details / Snooze) — deferred to v2 per design doc.

**Verified:**
- After re-adding the bot, `user_chat_connections` row was `connected` with `dm_space_name=spaces/0bHZCyAAAAE`.
- `curl POST /dev/google-chat/test-dm` with `{email: developer2@guardianhha.com, text: "..."}` returned `{"sent":true,"dm_space_name":"spaces/0bHZCyAAAAE"}` HTTP 200.
- The test message appeared in `developer2@guardianhha.com`'s Google Chat as a fresh bot DM in real time. Confirmed visually.

**Production safety:** the dev test endpoint will 404 anywhere `NODE_ENV=production`. No auth or rate-limiting required because the gate is environmental. Remove or further-restrict if it ever proves load-bearing in CI/staging.

### 9. Email channel adapter ✅

**Done:**
- [email-channel.service.ts](../../../src/models/notifications/services/channels/email-channel.service.ts) — thin wrapper. Single v1 method `send(toEmail, subject, html, text?): Promise<void>` that delegates to a new `EmailService.sendNotification(...)` primitive.
- Added `sendNotification` method to [EmailService](../../../src/common/services/email/email.service.ts) — generic SMTP path that mirrors the existing template-specific methods (auth check, mail options with logo attachment, transporter call, masked-email logging). Auto-derives plain text from HTML if `text` is not provided.
- Renamed dev test controller from `GoogleChatDevController` → `NotificationsDevController` (file: [notifications-dev.controller.ts](../../../src/models/notifications/controllers/notifications-dev.controller.ts)) and route prefix from `/dev/google-chat` → `/dev/notifications` since it now covers both channels. Endpoints: `POST /dev/notifications/test-chat-dm` and `POST /dev/notifications/test-email`. Both 404 in `NODE_ENV=production`.
- `NotificationsModule` now imports `EmailModule` (to inject `EmailService` into `EmailChannelService`), provides + exports `EmailChannelService`.
- Templates intentionally **not** in this module — module 10 (dispatcher) owns rendering. The channel adapters are dumb pipes: chat takes raw text, email takes pre-rendered subject + html.

**Verified:** `curl POST /dev/notifications/test-email` to `4aniqqjavedd4493@gmail.com` returned `{"sent":true,"to":"..."}` HTTP 200, and the email landed in the inbox with the expected subject/body. Confirmed visually.

**Asymmetry note:** the chat channel takes raw `text` while the email channel takes `subject + html` because email is a structured medium (subject line, mime type) and chat is just a string. The dispatcher (module 10) will render both formats and call the appropriate channel.

### 10. Dispatcher service ✅

**Done:**
- [notification-dispatcher.service.ts](../../../src/models/notifications/services/notification-dispatcher.service.ts) — single `dispatch(input: DispatchInput): Promise<DispatchResult>` entrypoint. `DispatchInput` carries `(orgId, userId, documentId, documentType, documentName, expiryDate, reminderKind)`; the cron scanner (module 11) will produce these.
- **Channel selection:** Chat if connection exists AND `status='connected'` AND `chat_eligible=true` AND `dm_space_name` is set; else email. Implemented in `canUseChat()`.
- **Idempotency:** before sending, look up `notification_dispatch_log` for a row with `(user_id, document_id, reminder_kind, status='sent')` regardless of channel. If found → return `{status: 'skipped', reason: 'already-sent'}` without sending or logging. Once a reminder is delivered through *any* channel, it stays delivered.
- **Retry + fallback:** Chat sends are retried up to 2 times. If all attempts fail, the Chat failure is logged (channel=`google_chat`, status=`failed`, error captured), and the dispatcher falls through to email.
- **Render:** v1 uses inline TS templates (no Handlebars yet — will extract when there are >2 templates). Two formats per dispatch — chat plain text + email HTML — with personalized greeting (`firstName`), document name, expiry date, and a deep-link to `${HOME_HEALTH_AI_URL}/employee/documents/${documentId}`. `reminder_kind='expired'` flips the headline copy to "{name} has expired" instead of "expires in N days".
- **Log writing:** uses upsert pattern (find by unique key + update, or insert). Failed attempts can be retried later — the existing `failed` row gets updated to `sent` when a subsequent attempt succeeds. No unique constraint violations.
- Dev test endpoint `POST /dev/notifications/test-dispatch` accepts `{email, documentId, documentType, documentName, expiryDate, reminderKind}` and runs the full dispatch path; returns `DispatchResult & {user_id, org_id}`.

**Verified:** three scenarios run via curl, all returned the expected `DispatchResult` shape and produced the right `notification_dispatch_log` rows:
1. **Chat path** — `developer2@guardianhha.com` (connected + eligible) with TB Test 7d reminder → `{channel: google_chat, status: sent}`. Log row inserted.
2. **Idempotency** — same call again → `{channel: google_chat, status: skipped, reason: already-sent}`. **No** new log row inserted.
3. **Email fallback** — flipped `chat_eligible=false` in DB → dispatched a Nursing License 14d reminder → `{channel: email, status: sent}`. Log row inserted with channel=email. (DB chat_eligible flag restored after the test.)

Dispatch log queried directly via psql confirms only the two `sent` rows exist; idempotent skip wrote nothing.

**Not yet verified:** Chat retry-and-fallback path (would require synthetically failing the Chat API call to exercise it). The code path is straightforward, the channel adapter throws on failure, the dispatcher catches and falls through. Will get exercised naturally if Google's API has a transient failure in real use.

### 11. Document expiry scanner (cron) ✅

**Done:**
- `@nestjs/schedule` installed; `ScheduleModule.forRoot()` wired into [AppModule](../../../src/app.module.ts).
- [document-expiry-scanner.service.ts](../../../src/models/notifications/services/document-expiry-scanner.service.ts) — `@Cron('0 8 * * *', { name: 'document-expiry-scan' })` daily at 8am UTC.
- Public `runScan(referenceDate?: Date): Promise<ScanResult>` for manual triggering and date simulation. The cron handler is a thin wrapper over it.
- For each `organization_integrations` row with `provider='google_chat' AND status='active'`, the scanner reads cadence from `config.cadence` (falls back to `[60d, 30d, 14d, 7d, 1d, expired]`), then for each cadence entry computes a one-day window `[target, target+1d)` where `target = referenceDate + days_before`, queries `inservice_completions` for rows whose `expiration_at` falls in that window (joined to `employees` filtered by `organization_id` and `deleted_at IS NULL`), and calls `dispatcher.dispatch(...)` per match.
- Returns a tally `{ orgsScanned, candidatesFound, dispatched, skipped, failed }` so cron output (and the dev endpoint) shows what happened at a glance.
- Dev endpoint `POST /dev/notifications/run-scan` accepts optional `{ referenceDate }` to simulate "today" for testing.
- v1 walks **inservice_completions only**. `employee_documents` doesn't have an `expiry_date` column today (only `hr_document_types.has_expiration: bool`), and `provider_profiles.license_expiration` / `organization_profiles.*_expiration` are org-level, not employee-level. When the schema gets per-document expiry (or OCR populates it), wire that source into the scanner alongside `findInserviceCandidates`.
- 💤 Per-org local-time scheduling — deferred to v2.

**Verified:**
- Seeded an `employees` row + `inservice_trainings` row + `inservice_completion` row for `developer2@guardianhha.com` with `expiration_at = NOW() + 7 days`.
- `curl POST /dev/notifications/run-scan` → `{orgsScanned: 1, candidatesFound: 1, dispatched: 1, skipped: 0, failed: 0}` → new `notification_dispatch_log` row inserted: `(document_type=inservice_completion, reminder_kind=7d, channel=google_chat, status=sent)`. The Chat DM (rendered via dispatcher's templates: "📋 Bloodborne Pathogens Training expires in 7 days…") landed in `developer2@guardianhha.com`'s Google Chat in real time.
- Second `run-scan` immediately after → `{candidatesFound: 1, dispatched: 0, skipped: 1, failed: 0}`. dispatch_log row count unchanged at 3 — scanner-level idempotency confirmed via dispatcher's existing `(user_id, document_id, reminder_kind, status='sent')` check.

### 12. BullMQ producer + consumer ✅

**Done:**
- Installed `bullmq` + `@nestjs/bullmq`. Redis already running on `127.0.0.1:6379` (verified via `redis-cli ping`).
- Added `REDIS_HOST` / `REDIS_PORT` env vars; `BullModule.forRoot({ connection: ... })` wired in [AppModule](../../../src/app.module.ts).
- [reminder-dispatch.producer.ts](../../../src/jobs/producers/reminder-dispatch/reminder-dispatch.producer.ts) — exports `REMINDER_DISPATCH_QUEUE` constant + `ReminderDispatchProducer.enqueue(input)` that serializes the `DispatchInput` (Date → ISO string) and calls `queue.add('dispatch', payload, { jobId, attempts: 3, backoff: exponential, removeOnComplete: 1000, removeOnFail: 5000 })`. `jobId = ${userId}:${documentId}:${reminderKind}` so BullMQ dedupes at the queue level — the same scan running twice within the retention window doesn't enqueue a duplicate job.
- [reminder-dispatch.consumer.ts](../../../src/jobs/consumers/reminder-dispatch/reminder-dispatch.consumer.ts) — `WorkerHost` Processor with `concurrency: 5` and `limiter: { max: 10, duration: 1000 }` (10 jobs/sec). Calls `dispatcher.dispatch(...)` with the deserialized payload. Throws on `failed` to trigger BullMQ's retry logic; returns the result on `sent` or `skipped`.
- [Scanner](../../../src/models/notifications/services/document-expiry-scanner.service.ts) refactored: previously called `dispatcher.dispatch(...)` inline; now calls `producer.enqueue(...)`. `ScanResult` shape changed from `{dispatched, skipped, failed}` to `{enqueued, malformed}` — the scanner no longer knows the dispatch outcome (consumer does), only how many jobs it submitted.
- Module wires the queue via `BullModule.registerQueue({ name: REMINDER_DISPATCH_QUEUE })` and registers the producer + consumer as providers.

**Idempotency now stacks across two layers:**
1. **Queue level** — BullMQ rejects duplicate `jobId` while the original is still within `removeOnComplete: 1000` retention. Catches "scanner ran twice in quick succession."
2. **Dispatcher level** — checks `notification_dispatch_log` for `(user_id, document_id, reminder_kind, status='sent')`. Catches "scanner ran days apart but reminder already delivered." Already proven in module 10.

**Rate-limiting rationale:** Google Chat API quotas apply per-app, so all tenants share one bucket. The 10 jobs/sec limiter on the consumer prevents a 5,000-employee morning scan from bursting Google's quota.

**Verified:**
- After fixing a TS compile error in the dev controller (stale `result.dispatched` reference) that had silently kept the watch-mode server on old code: scan response shape flipped to `{enqueued: 1, malformed: 0}` confirming refactor live.
- Cleared `notification_dispatch_log` row for the seeded inservice_completion → ran scan → got `{enqueued: 1}` → waited 3s → dispatch_log gained a fresh `(inservice_completion, 7d, google_chat, sent)` row. The full async pipeline (scanner → queue → consumer → dispatcher → channel → Google Chat API → DB) end-to-end.
- Ran scan a second time without clearing the log → response still `{enqueued: 1}` (scanner doesn't peek the log) but dispatch_log row count stayed at 3, proving the two-layer idempotency holds across queue + dispatcher.

### 13. Org admin API endpoints ✅

**Done:**
- [organization-integration.service.ts](../../../src/models/notifications/services/organization-integration.service.ts) — six business-logic methods: `enable`, `verify`, `updateConfig`, `disable`, `getStatus`, `listEmployees`. All scoped to one org × `provider='google_chat'` row.
- [organization-integrations.controller.ts](../../../src/models/notifications/controllers/organization-integrations.controller.ts) — REST surface at `/v1/api/organizations/:organizationId/integrations/google-chat`. Guarded by `@UseGuards(JwtAuthGuard, IntegrationAdminGuard)`.
- [integration-admin.guard.ts](../../../src/models/notifications/guards/integration-admin.guard.ts) — custom guard that allows access if the actor is **either** the org owner (`organizations.user_id` matches) **or** an ACTIVE staff member with role `HR`/`MANAGER`. Replaced an initial implementation that used the project-wide `OrganizationRoleGuard` only, which wrongly blocked the org owner from managing their own integration unless they were also explicitly added as staff. Resolves design-doc open question #3 with the broader scope (owner + HR/MANAGER staff).
- DTOs at [enable-google-chat.dto.ts](../../../src/models/notifications/dto/enable-google-chat.dto.ts) and [update-google-chat-config.dto.ts](../../../src/models/notifications/dto/update-google-chat-config.dto.ts) — class-validator on workspace-domain regex and cadence enum.
- Email-domain match validation in `enable()`: rejects with 400 when `workspace_domain ≠ actor.email`'s domain. Implements architectural decision #4.
- `verify()` flow: looks up the actor's own `user_chat_connection`. If status≠connected → 400 with instructions to add the bot first. Otherwise sends a real "✅ verified" DM via `GoogleChatChannelService` and on success flips `status=active` + sets `verified_at`. Errors during the test DM bubble up as 400 with the underlying message.
- `listEmployees()` finds users in the org by union of three membership signals (owner + ACTIVE staff + ACTIVE employees per architectural decision #8), dedupes by user_id, joins `users` for name/email and `user_chat_connections` for Chat status. Returns each entry as one of `connected | not_connected | email_only | revoked` plus a `summary` rollup of counts. Originally checked only `organization_staff`, which produced an empty list when the org used `employees` instead of `organization_staff` to track non-admin members.
- Module wiring: `NotificationsModule` imports `OrganizationsModule` (for the `OrganizationRoleGuard` provider it exports) and `AuthenticationModule` (for the JWT strategy).

**Endpoints (all under `/v1/api/organizations/:organizationId/integrations/google-chat`):**

| Method | Path suffix | Purpose |
|---|---|---|
| GET | / | Read integration row; returns `{integration: ... \| null, install_url: string}` |
| POST | /enable | Upsert pending integration; validates `workspace_domain` matches admin's email domain |
| POST | /verify | Send a real test DM to the actor; flips status → active on success |
| PATCH | /config | Merge `{cadence?, fallback_to_email?, allow_personal_accounts?}` into config jsonb |
| POST | /disable | Status → disabled; `disabled_at` set |
| GET | /employees | List employees with their connection status + a summary count |

**`install_url` field on GET response:** the URL the wizard's "Install bot" button opens. Pre-Marketplace it falls back to the same Chat user-add deep link the employee flow uses (`https://chat.google.com/u/0/app/<APP_ID>`). Post-Marketplace, set the new env var `GOOGLE_CHAT_ADMIN_INSTALL_URL` to a direct admin-install URL (typically the install-modal-deep-link variant under `admin.google.com/ac/marketplace/app/.../install`) and the same response field carries the production URL — no frontend code change at flip-day. Computed by `OrganizationIntegrationService.getInstallUrl()`.

**Verified:** Set bcrypt password on `developer2@guardianhha.com`, logged in via `POST /v1/api/auth/login`, captured the JWT, ran each endpoint:
- ✅ GET returned existing seeded integration.
- ✅ POST enable with mismatched domain → 400 with the architectural-decision-#4 error message.
- ✅ POST enable with matching domain → 200, `enabled_by_user_id` populated, `updated_at` advanced.
- ✅ POST verify → 200, `verified_at` advanced, real DM "✅ HomeHealth Chat integration verified" landed in `developer2@guardianhha.com`'s Chat.
- ✅ PATCH config → 200, config jsonb now `{cadence: ['30d','7d','expired'], fallback_to_email: true}`.
- ✅ GET employees → returned `[{user_id, email, name, status: 'connected', connected_at}]` + summary `{connected:1, not_connected:0, email_only:0, revoked:0}`.
- ✅ POST disable → 200, status flipped to `disabled`, `disabled_at` set. POST enable again → status flipped back to `pending` (correct — disabled integrations require re-verification).

### 14. Org admin UI — setup wizard ❌

**Depends on:** module 13.

**Remaining:** frontend work, three steps per design doc: domain → install → cadence. Lives at "Settings → Integrations → Google Chat."

### 15. Org admin UI — manage page ❌

**Depends on:** module 13.

**Remaining:** frontend work — status, cadence editor, employee connection list, recent activity. Connection counts pull from `user_chat_connections` joined to org members.

### 16. Employee API endpoints ✅

**Done:**
- [employee-notifications.service.ts](../../../src/models/notifications/services/employee-notifications.service.ts) — three methods: `getStatus`, `connectChat`, `disconnectChat`. All scoped to the actor's `userId`.
- **Membership resolution** uses the union of three signals (per architectural decision #8): owner via `organizations.user_id`, staff via `organization_staff` with `status='ACTIVE'`, or employee via `employees` with status `ACTIVE`/`active`. Replaces an earlier implementation that only checked `organization_staff`, which incorrectly returned `org_integration_status: 'not_enabled'` for owners and regular employees who weren't staffed.
- [employee-notifications.controller.ts](../../../src/models/notifications/controllers/employee-notifications.controller.ts) — REST surface at `/v1/api/me/notifications`. Guarded by `JwtAuthGuard` only (no org-role check needed; the actor's identity comes from the JWT `sub` claim and we always operate on their own data).
- New env var `GOOGLE_CHAT_APP_ID=128879610173` (Chat app project number) → exposed via `GoogleChatConfigService.appId`. Used to build the Tier 2 deep link `https://chat.google.com/u/0/app/{APP_ID}` returned by `POST /chat/connect`.
- Tier-selection logic: reads `integration.config.installation_mode` (default `'whitelist'`). For v1 always returns Tier 2 (`{tier: 'deep_link', url: ...}`). Tier 3 (zero-click via `chat.spaces.findDirectMessage` + `messages.create`) is stubbed out with a comment for when Marketplace + domain-install ships.
- Personal-Gmail rejection: when the user's email domain doesn't match `integration.workspace_domain`, returns 400 with the canonical message — unless `config.allow_personal_accounts === true`, in which case it falls through to Tier 2.
- 💤 `POST /chat/test-reminder` (F7) — deferred. Frontend doc spec'd it but said "skip for v1."

**Endpoints (all under `/v1/api/me/notifications`):**

| Method | Path suffix | Purpose |
|---|---|---|
| GET | / | Returns `{email_destination, org_integration_status, workspace_domain, chat_connection}`. Frontend derives State 1–4 from this single payload. |
| POST | /chat/connect | Returns `{tier: 'deep_link' \| 'zero_click', url? \| connection?}`. 400 on personal-Gmail mismatch. |
| POST | /chat/disconnect | Calls `GoogleChatChannelService.leaveSpace` (best-effort) to remove the bot from the user's Chat, then flips `user_chat_connections.status` to `revoked` + sets `revoked_at`. **Pre-Marketplace, leaveSpace fails on DM spaces** because Google requires the Chat app to be Marketplace-published + admin-domain-installed before allowing `chat.spaces.members.delete` on DMs. The disconnect itself still succeeds (DB row flipped); user has to manually remove the bot from Chat for full client-side cleanup. Post-module-18 + admin domain-install, leaveSpace starts working with zero code change. The expected pre-Marketplace failure is logged at LOG (not WARN) level. |

**Verified:** Logged in as `developer2@guardianhha.com`, exercised:
- ✅ GET → returned current state (`org_integration_status: 'pending' / 'active'` per DB, `chat_connection: {status: 'connected' \| 'revoked', chat_eligible: true, connected_at: ...}`).
- ✅ POST disconnect → flipped DB row to `revoked` + `revoked_at`. Subsequent GET reflected the change.
- ✅ POST connect with org status `pending` → 400 "Your organization hasn't enabled Google Chat reminders yet." (the active-status precondition).
- ✅ POST connect with org status `active` → 200 `{tier: 'deep_link', url: 'https://chat.google.com/u/0/app/128879610173'}`.
- ✅ POST connect with `workspace_domain` ≠ user's email domain → 400 with the personal-account message.

### 17. Employee UI — notifications settings ❌

**Depends on:** module 16.

**Remaining:** frontend work — render states 1-4 per design doc. The "Connect Google Chat" button is the user-visible piece of the future Tier 2/Tier 3 enhancements (see "Future enhancements" below).

### 18. Marketplace publication ❌

**Run in parallel** with implementation modules — Google review takes weeks. Sequenced as five concrete sub-stages:

**18a. Pre-submission preparation**
- Privacy policy URL covering Chat data handling (what we read from events, what we send to Chat, retention, employee opt-out).
- Terms of service URL.
- Demo video (~2 min) showing the full integration flow: org admin enables → employee connects → reminder DM lands.
- Detailed listing description, support email, support URL.
- Logo + listing screenshots.
- Internal CASA / security review if required by Google's tier (currently `chat.bot` scope only is the lightest tier; verify at submission time).

**18b. Production GCP project (module 2)**
- Block-on: module 2 (prod GCP project) created under HomeHealth's own Workspace tenant.
- Mirror dev Chat app config (name, avatar, description, scopes, endpoint).
- Service account created and JSON downloaded into prod secrets manager.

**18c. OAuth verification**
- Required for any sensitive scopes; for `chat.bot` it tends to be lighter but still requires policy URLs + sometimes a CASA review.
- Submit via Google Cloud Console → APIs & Services → OAuth consent screen → "Submit for verification."
- Respond to reviewer feedback. Allow several rounds, weeks each.

**18d. Marketplace listing creation**
- Create listing in Marketplace SDK (Cloud Console → Marketplace SDK → Configure listing).
- Upload listing assets (logo, banner, screenshots, demo video).
- Set distribution: "Public" or "Specific Workspace domains" if doing private rollout first.
- Submit for Marketplace review.
- Respond to Marketplace-team feedback (separate review queue from OAuth).

**18e. Post-approval flip**
- Set `GOOGLE_CHAT_ADMIN_INSTALL_URL` in prod `.env` to the Marketplace direct-install URL (`https://admin.google.com/ac/marketplace/app/.../install` variant — drops the admin straight onto the install confirmation modal, single click).
- Switch the Chat API config visibility from "Available to specific people and groups" to "Available to everyone in your organization" (or public, depending on rollout strategy).
- Update the org-admin wizard step 2 copy in the frontend doc to reflect that the Marketplace listing is now real.
- Optional: ship F8 (webhook-based auto-install detection) so the "Verify install" button gets replaced by an auto-advancing spinner.

### 19. Local dev infrastructure 🚧

**Done:**
- ngrok tunnel pattern proven (`ngrok http 8000` → `https://*.ngrok-free.dev/webhooks/google-chat/events`).
- Round-trip tested through tunnel.

**Remaining:**
- Reserve a free static ngrok domain (one-time at https://dashboard.ngrok.com/domains) so the URL stops rotating between sessions.
- Update Google Console URL to that static domain once.
- Optionally: add `hh-tunnel` shell alias.

## Future enhancements

Items planned beyond v1 — captured here so they don't fall off the radar.

### F1. "Connect Google Chat" button — Tier 2 deep-link

**What:** Button in the employee Notifications page (state 2 from the design doc) that opens Google Chat directly at the bot's "Add" page, instead of asking the user to search for it.

**URL pattern:**
```
https://chat.google.com/u/0/app/<APP_ID>
```
(`<APP_ID>` = the Chat API project number — e.g., `128879610173` for the dev project.)

**UX:** click → Chat opens in new tab on bot page → user clicks Add → existing `ADDED_TO_SPACE` flow links them. **One Google click, no search.**

**Available when:** today, against current dev visibility allowlist. No backend changes required — pure frontend.

**Module dependency:** part of module 17 (employee UI). Implement as the default path for state 2.

### F2. "Connect Google Chat" button — Tier 3 zero-click

**What:** Truly one-click connect from inside HomeHealth. Employee clicks the button → backend calls Chat API to create/find the DM space and send the welcome message → bot appears in the employee's Chat with no further action from them.

**How:**
1. Backend calls `chat.spaces.findDirectMessage` for the user's resource name (or `spaces.create` with `singleUserBotDm: true`).
2. Backend calls `chat.spaces.messages.create` with the welcome text.
3. Persist the `user_chat_connections` row server-side (no need to wait for `ADDED_TO_SPACE` event).

**Available when:** **prod-only**, after two preconditions:
1. Module 18 (Marketplace publication) ships and the app is publicly listed.
2. The customer org's Workspace admin has installed the bot for the entire domain via Marketplace ("Install for everyone in this organization"). Domain install pre-authorizes the bot for every employee, which is what makes zero-click possible.

**Implementation strategy:** the same employee-facing button (F1) just changes its handler. In dev: opens deep link. In prod (post-Marketplace, post-admin-install): POSTs to `/api/me/notifications/connect-chat` → backend does the API dance. The button stays in the same place; only the action changes based on `organization_integrations.status` + `installation_mode`.

### F3. Cards v2 with action buttons in reminder DMs

Replace plain-text reminder DMs with [Cards v2](https://developers.google.com/chat/api/guides/v1/messages/create#cards) carrying:
- Header (document name)
- Body (expiry date, days remaining)
- Buttons: "Upload now" (deep link to HH portal), "View details," "Snooze 7 days" (requires interactive event handling).

Snooze button requires extending the webhook to handle `CARD_CLICKED` events.

### F4. `notification_preferences` table

Per-employee per-channel mute toggles. Currently we infer "channel = chat if eligible else email" — this lets employees override. Defer until employees actually ask for it.

### F5. Per-org local-time scheduling

Currently the cron fires at 8am UTC for all tenants. Future: each org configures its preferred time zone, scanner respects it. Requires a `timezone` column on `organization_integrations.config`.

### F6. Bulk "send invite reminder" admin action

In the org-admin manage page, an action that emails all employees with `chat_eligible=true` but `status != 'connected'`, prompting them to connect. Useful at rollout.

### F7. Per-employee "send test reminder" button

In the employee Notifications page (state 3), a button that sends a sample reminder DM so the employee can verify it works before a real document expires.

### F8. Webhook-based auto-detection of Workspace install

**What:** when a customer's Workspace admin installs the Chat app for their domain via Marketplace, automatically flip `organization_integrations.status` from `pending` to `active` without requiring the admin to come back to HomeHealth and click "Verify install."

**How:**
1. In Google Cloud Console → Chat API → Configuration, configure the install/setup-completion event endpoint to point at the existing `/webhooks/google-chat/events` URL.
2. Extend [BotEventHandlerService](../../../src/models/notifications/services/bot-event-handler.service.ts) to handle the install event type — parse the event's domain (`hd` claim or `domainId`), look up the matching `organization_integrations` row in `pending` state by `workspace_domain`, flip to `active`, set `verified_at`.
3. Frontend: replace the "Verify install" button with an auto-polling spinner ("Waiting for install confirmation from Google...") that watches `GET /` for `status === 'active'` and auto-advances the wizard.

**Why deferred:** this is a UX polish on top of module 18. The current "click Verify install" button works — it just requires one extra deliberate action from the admin. Worth doing **immediately after Marketplace publication**, since pre-Marketplace the install path varies enough that the manual verify is more reliable.

**Estimated effort:** ~1-2 days backend (webhook + event parsing + matching), ~half day frontend (polling state machine + spinner UI).

**Module dependency:** part of module 18's post-approval flip, or shipped as a follow-up.

## Working agreements

- **Edit in place.** Status flips from ❌ → 🚧 → ✅ on the same line; don't add "completed on date" rows.
- **Files first, status second.** When a module ships, link to the actual file paths in the "Done" section so readers can jump from plan to code.
- **One decision, one place.** If a question is resolved in [integration-google-chat.md](integration-google-chat.md), don't restate the decision here — just reference it.
- **Future enhancements stay numbered (F1, F2, …).** When one is implemented, move it into the relevant module section and strike it from "Future enhancements" — don't renumber survivors.
- **Every module ends with a verification step.** A module is not ✅ until its behavior is exercised end-to-end and proven to work — a curl, a real Chat event, a DB query, a UI flow, or whatever fits the module. Capture the verification under a **Verified:** subsection alongside **Done:** so it's clear *how* we know the module works, not just that the code was written. Untested code does not flip the status to ✅.

## Docs structure

Integration documentation lives under `docs/integration-google-chat/`, split by where the work happens:

```
docs/integration-google-chat/
  backend/
    integration-google-chat.md                  design doc
    integration-google-chat-plan.md             execution plan (this file)
  frontend/
    integration-google-chat-frontend.md         frontend handoff guide (consumed by HH-Frontend devs)
```

The frontend guide was created as the handoff document the moment a real frontend developer needed to start work on the UI. It contains: API contracts (live + planned), the four employee states, the three-step org-admin wizard, copy/wording, design-system pointers (cross-references HH-Frontend's `employee-portal-ui` skill), suggested route layout, and a testing checklist. Frontend implementation changes get logged there from now on — don't backflow them into the backend design doc.

Path notes:
- From `docs/integration-google-chat/backend/`, source files are at `../../../src/...`.
- Sibling docs in the same folder are referenced bare: `[integration-google-chat.md](integration-google-chat.md)`.
- Cross-folder references (when frontend exists): `[../frontend/integration-google-chat-frontend.md](../frontend/integration-google-chat-frontend.md)`.

The [google-chat-integration-docs skill](../../../.claude/skills/google-chat-integration-docs/SKILL.md) enforces this structure and tells future contributors which file to update for which kind of change.
