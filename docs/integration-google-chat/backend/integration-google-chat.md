# Google Chat Integration — Implementation Plan

## Goal

Send document-expiration reminders (license, TB report, HR documents, compliance documents, in-service trainings, etc.) to employees as DMs in Google Chat, with email as the fallback channel.

## Context & constraints

- **HomeHealth is multi-tenant.** Customer organizations (Guardian HHA, etc.) are tenants in HomeHealth. Each tenant has its own Google Workspace (`guardianhha.com`, `acmehha.com`, …) and its own employees.
- **One Chat app, owned by HomeHealth.** Registered in HomeHealth's Google Cloud project. Each customer org's Workspace admin installs it for their domain via the Google Workspace Marketplace.
- **Bot-auth model.** The bot DMs employees using its own service-account credentials. No per-employee OAuth tokens to manage.
- **Personal Google accounts (`@gmail.com`) are not supported as a Chat channel.** Those employees are full employees in every other respect — they just receive reminders by email instead. This is a compliance-driven decision (HIPAA BAA covers Workspace, not consumer Gmail) and a control-plane decision (the customer org's IT can't manage personal accounts).

## Architectural decisions

1. **Chat app distribution: Google Workspace Marketplace, public listing.** Required because each customer org is a separate Workspace.
2. **Auth model: bot-auth (service account).** Simpler than per-employee OAuth, no token refresh, no scary consent screens.
3. **Org install model: Workspace-admin installs via Marketplace.** HomeHealth's UI orchestrates and verifies but doesn't drive the install itself — the actual install click happens in admin.google.com.
4. **Domain-claim safety: email-domain match.** When an HH org admin types their Workspace domain, validate it matches the admin's own email domain. Prevents tenants from claiming each other's domains.
5. **Org-side bot resolution: lookup `users.email = event.user.email`.** When the bot's webhook fires, identify the HomeHealth user by email match.
6. **Personal-Gmail handling: `chat_eligible = false`, route to email.** No feature restriction — just a different notification channel for that subset.
7. **Idempotency: unique constraint on dispatch log.** `(user_id, document_id, reminder_kind, channel)` cannot be duplicated, so a re-run of the cron is safe.
8. **Membership for the integration is the union of three signals: owner + staff + employee.** A user "belongs" to an org if any of these holds: (a) they are the owner via `organizations.user_id`, (b) they have an `organization_staff` row with `status='ACTIVE'`, or (c) they have an `employees` row with status `ACTIVE`/`active`. The rule is enforced in **four** places — keep them in sync:
   - `IntegrationAdminGuard` (admin-side: owner OR HR/MANAGER staff).
   - `EmployeeNotificationsService.findUsersOrgIntegration` (employee GET-state endpoint, derives State 1–4).
   - `BotEventHandlerService.handleAddedToSpace` (bot-add webhook, creates the `user_chat_connections` row).
   - `OrganizationIntegrationService.listEmployees` (admin manage page's employee list — finds users *in* an org by union of the three signals on that org).
   All four were originally written checking `organization_staff` only, which incorrectly blocked owners and regular employees from the integration and gave the manage page an empty list.

## 🚧 Phase 0 — Google Cloud setup (devops, no code)

Dev project is set up; prod project + Marketplace submission still pending.

1. ✅ **Dev project**: `homehealth-reminders-dev` created (currently hosted under Guardian Workspace tenant for dev iteration). ❌ **Prod project**: not yet created — must be created under HomeHealth's own Workspace tenant (e.g. `homehealth.ai`), since the home-org of the Chat app determines Marketplace ownership.
2. ✅ **Google Chat API** enabled on dev project.
3. ✅ **Chat app configured** on dev:
   - Name: "HomeHealth Reminders"
   - "Build this Chat app as a Workspace add-on" — **unchecked** (we want a Chat bot, not a Workspace add-on).
   - Avatar, description filled.
   - Interactive features enabled.
   - Functionality → "Join spaces and group conversations" — unchecked (DMs only).
   - Connection settings: HTTP endpoint URL → currently a placeholder; updated per session to point at the active ngrok tunnel.
   - Authentication Audience: `HTTP endpoint URL`.
   - Triggers: "Use a common HTTP endpoint URL for all triggers" → `<ngrok>/webhooks/google-chat/events`.
   - Visibility: "Available to specific people and groups" with `developer2@guardianhha.com` whitelisted.
   - Logs → errors to Logging enabled.
4. ✅ **OAuth consent screen** configured (minimal — no user OAuth scopes needed for bot-auth).
5. ✅ **Service account** `homehealth-chat-bot` created on dev project; JSON key downloaded (must be stored as `GOOGLE_CHAT_SERVICE_ACCOUNT_JSON` in backend secrets — not yet wired).
6. ❌ **OAuth verification + Marketplace listing review** — not yet started. Long pole; weeks of Google review. Required artifacts: privacy policy, terms of service, demo video, security questionnaire. Run in parallel with prod project creation under HomeHealth's Workspace tenant.

## ✅ Phase 1 — Data model & config plumbing

Migrations applied to dev DB; entities created and wired into `NotificationsModule`.

### Migrations

#### `create_organization_integrations`
```
id                  uuid pk
org_id              uuid fk → organizations
provider            varchar(32)            -- 'google_chat' (future-proof for slack/teams)
status              varchar(16)            -- 'pending' | 'active' | 'disabled'
workspace_domain    varchar(255)           -- e.g. 'guardianhha.com'
config              jsonb                  -- cadence, fallback rules, allow_personal_accounts
enabled_by_user_id  uuid fk → users
enabled_at          timestamptz
verified_at         timestamptz
disabled_at         timestamptz
created_at          timestamptz
updated_at          timestamptz

unique (org_id, provider)
```

#### `create_user_chat_connections`
```
id              uuid pk
user_id         uuid fk → users
org_id          uuid fk → organizations    -- denormalized for per-tenant queries
provider        varchar(32)
chat_user_id    varchar(255)               -- Google's stable user resource name
dm_space_name   varchar(255)               -- 'spaces/AAAA...' returned on first hello
status          varchar(16)                -- 'pending' | 'connected' | 'revoked'
chat_eligible   boolean                    -- false for personal-Gmail employees
connected_at    timestamptz
revoked_at      timestamptz
created_at      timestamptz
updated_at      timestamptz

unique (user_id, provider)
```

#### `create_notification_dispatch_log`
```
id              uuid pk
org_id          uuid
user_id         uuid
document_id     uuid
document_type   varchar(64)
reminder_kind   varchar(32)                -- '60d' | '30d' | '14d' | '7d' | '1d' | 'expired'
channel         varchar(16)                -- 'google_chat' | 'email'
status          varchar(16)                -- 'sent' | 'failed' | 'skipped'
error           text
sent_at         timestamptz

unique (user_id, document_id, reminder_kind, channel)   -- idempotency
```

#### (v2, optional) `create_notification_preferences`
Per-employee per-channel mute toggles. Defer until v2.

### NestJS module layout

```
src/
  config/google-chat/
    configuration.ts                         GOOGLE_CHAT_SERVICE_ACCOUNT_JSON, app name, webhook secret
    config.module.ts
    config.service.ts
  models/notifications/
    entities/
      organization-integration.entity.ts
      user-chat-connection.entity.ts
      notification-dispatch-log.entity.ts
    dto/
      enable-integration.dto.ts
      update-cadence.dto.ts
      verify-integration.dto.ts
    services/
      organization-integration.service.ts
      user-chat-connection.service.ts
      notification-dispatcher.service.ts
      document-expiry-scanner.service.ts
      channels/
        email-channel.service.ts             wraps existing EmailService
        google-chat-channel.service.ts       wraps Chat API client
    controllers/
      organization-integrations.controller.ts    /api/orgs/:orgId/integrations
      employee-notifications.controller.ts       /api/me/notifications
      google-chat-events.controller.ts           POST /webhooks/google-chat/events
    notifications.module.ts
  jobs/
    producers/reminder-scan.producer.ts
    consumers/reminder-dispatch.consumer.ts
  database/migrations/
    [date]-create-organization-integrations.ts
    [date]-create-user-chat-connections.ts
    [date]-create-notification-dispatch-log.ts
```

New dependencies: `@nestjs/schedule` for the cron, `@googleapis/chat` + `google-auth-library` for the Chat client (do **not** use the full `googleapis` meta-package — see module 7 plan note).

## ✅ Phase 2 — Bot event endpoint (enables employee linking)

**Current state:** real handlers backed by DB lookups; signature verification active; round-trip tested end-to-end with `ADDED_TO_SPACE` creating a real `user_chat_connections` row and `REMOVED_FROM_SPACE` flipping it to `revoked`.

Files in place:
- [google-chat-events.controller.ts](../../../src/models/notifications/controllers/google-chat-events.controller.ts) — `GET` (health, unguarded) + `POST` (events, guarded) at `/webhooks/google-chat/events`. Delegates business logic to the handler service.
- [bot-event-handler.service.ts](../../../src/models/notifications/services/bot-event-handler.service.ts) — encapsulates the real `ADDED_TO_SPACE` / `REMOVED_FROM_SPACE` / `MESSAGE` logic. Injects `User`, `OrganizationStaff`, `OrganizationIntegration`, `UserChatConnection` repositories via `TypeOrmModule.forFeature`.
- [notifications.module.ts](../../../src/models/notifications/notifications.module.ts) — registers the controller, the guard, the handler service, and all needed entities.

Google Chat calls `POST /webhooks/google-chat/events` whenever something happens. Three event types:

### `ADDED_TO_SPACE`
Employee added the bot to their Chat. Payload contains `event.user.email`, `event.user.name` (Chat user resource), `event.space.name` (DM space).

Implemented flow (see `bot-event-handler.service.ts`):

```
1. Guard: verify the request signature (Google bearer-token scheme).
2. Look up users.email = event.user.email.
   - Not found → reply "This Google account isn't linked to any HomeHealth employee. Ask your admin to add {email} to HomeHealth first."
3. Find organization_staff rows where user_id = user.id AND status = 'ACTIVE'.
   - None → reply "Your HomeHealth account isn't currently active in any organization."
4. Find organization_integrations where provider='google_chat' AND status='active' AND org_id IN (active org_ids).
   - None → reply "Your organization hasn't enabled HomeHealth Chat reminders yet."
   - Multiple → pick the first (cross-tenant employee, see open question #4) and log a warning.
5. Compute chat_eligible = (email's domain matches integration.workspace_domain), or true if workspace_domain is null.
6. Upsert user_chat_connections row:
     - status = 'connected'
     - chat_user_id = event.user.name
     - dm_space_name = event.space.name
     - chat_eligible = (from step 5)
     - connected_at = now
     - revoked_at = null
7. Reply:
     - chat_eligible = true:  "Hi {name}, you're connected to HomeHealth Reminders. I'll DM you about expiring documents."
     - chat_eligible = false: "Hi {name}, this account ({email}) isn't on your organization's Google Workspace, so document reminders will continue to be sent by email instead of Chat."
```

### `REMOVED_FROM_SPACE`
Employee removed the bot. Look up `user_chat_connections` for that email; if found, set `status = 'revoked'` and `revoked_at = now`. Silently no-ops if no connection exists.

### `MESSAGE`
Employee replied to a reminder. v1: `"This is a notifications-only bot. Open HomeHealth to manage."` v2: snooze / acknowledge buttons.

### Security
✅ **Implemented.** Every `POST /webhooks/google-chat/events` request must carry a valid `Authorization: Bearer <jwt>` header. The guard ([google-chat-request.guard.ts](../../../src/models/notifications/guards/google-chat-request.guard.ts)) fetches Google's X.509 certs (1-hour cached) and verifies signature + issuer + email + optionally audience.

**JWT structure (verified empirically, not just from docs):**
- `iss = https://accounts.google.com` (Google's standard OIDC issuer — same for all Google tokens)
- `email = chat@system.gserviceaccount.com` (this is what identifies the token as specifically from Chat)
- `aud = <full webhook URL>` when "Authentication Audience" is set to "HTTP endpoint URL" in the Chat API config
- Signed with Google's general OIDC keys at `https://www.googleapis.com/oauth2/v1/certs`, **not** the chat service account's individual keys at `service_accounts/v1/metadata/x509/chat@...` (those exist but aren't the ones Google uses to sign Chat events).

**Verification flow:**
1. Fetch certs from `oauth2/v1/certs` (cached).
2. Match cert by `kid` in JWT header.
3. `jsonwebtoken.verify` checks RS256 signature, `iss = https://accounts.google.com`, and `aud` (if configured).
4. Manually check `payload.email = chat@system.gserviceaccount.com` to confirm the token came from Chat (not another Google service).

**Env vars:**
- `GOOGLE_CHAT_VERIFY_SIGNATURE` (default `true`) — set to `false` only in dev to allow curl without crafting real JWTs.
- `GOOGLE_CHAT_AUDIENCE` (optional) — when set, JWT `aud` must match. Equals the value Google's "Authentication Audience" dropdown produces (the webhook URL or the GCP project number). Leave empty to skip audience check while ngrok URLs rotate.
- `GOOGLE_CHAT_ISSUER` (default `chat@system.gserviceaccount.com`) — the expected `email` claim, not the JWT `iss`. Name kept for env-var stability; don't change unless Google does.

## ✅ Phase 3 — Dispatcher, scanner & cron

The full async pipeline is live: a daily `@Cron` walks `inservice_completions` per active org × cadence kind, enqueues `reminder-dispatch` jobs (jobId = `userId:documentId:reminderKind` for queue-level dedupe), and a rate-limited BullMQ consumer (`concurrency: 5`, `limiter: 10/sec`) feeds each job into the dispatcher, which picks Chat-or-email, renders, sends, and writes the dispatch log idempotently.

### The scanner (cron)

Daily `@Cron('0 8 * * *')` — 8am UTC for v1 (per-org timezone in v2):

```
For each org with organization_integrations.status='active':
  For each compliance/HR document with expiry_date:
    For each reminder_kind in ['60d','30d','14d','7d','1d','expired']:
      If today == expiry_date - kind_offset:
        If no notification_dispatch_log row exists for (user, doc, kind, *):
          Enqueue 'reminder-dispatch' job with (user_id, doc_id, kind).
```

Idempotency comes from the unique constraint on the dispatch log + the existence check.

### The dispatcher (BullMQ consumer)

Receives `(user_id, doc_id, kind)`:

```
1. Load user, org integration, chat connection.
2. Choose channel:
     - 'google_chat' if connection.status = 'connected' AND chat_eligible.
     - else 'email'.
3. Render message template (subject, body, deep link to HH portal).
4. Call channel adapter:
     - On Chat failure: retry once, fall back to email.
     - On email failure: log, raise alert.
5. Insert notification_dispatch_log row with the result.
```

### Email channel
`EmailChannelService.send(toEmail, subject, html, text?)` wraps a new `EmailService.sendNotification(...)` primitive that mirrors the existing template-specific methods (auth check, mailer-with-logo, masked-email logging). Channel takes **pre-rendered** subject and html — the dispatcher (this phase) owns rendering. Templates live with the dispatcher, not the channel, so adding a new reminder type doesn't require changing the channel adapter.

### Chat channel
Uses `@googleapis/chat` (the per-API package — the full `googleapis` meta-package OOMs the TypeScript compiler in dev, see module 7 in the plan). The authenticated client is provided by `GoogleChatClientService`:

```typescript
const client = this.googleChatClient.getClient();
await client.spaces.messages.create({
  parent: connection.dm_space_name,
  requestBody: { text: '...' /* or cardsV2 */ },
});
```

For richer messages, use **cardsV2** with header (document name), body (expiry date), and a button linking back to the HH employee portal.

### What an actual reminder looks like in Chat

```
HomeHealth Reminders                              now
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 Your TB Test expires in 7 days

Document:   TB Test
Expires:    May 8, 2026 (in 7 days)

Please upload the renewed document to stay compliant.

[ Upload now ]   [ View details ]
```

Buttons deep-link to the employee portal with the doc preselected.

## Phase 4 — Organization admin UI

Lives at `Settings → Integrations → Google Chat`.

### Screen A — Integrations list (entry point)

A list of available integrations. Each card:

```
┌───────────────────────────────────────────────┐
│ Google Chat                                    │
│ Send document expiration reminders to         │
│ employees via Google Chat DM.                 │
│                                                │
│ Status: Not connected      [ Set up ]         │
└───────────────────────────────────────────────┘
```

After enabling: `Status: Active · 12 of 18 employees connected · [Manage]`.

### Screen B — Setup wizard (3 steps)

#### Step 1 — Workspace domain
- Input: *"What's your Google Workspace domain?"* prefilled from the admin's own email domain.
- Validation: domain must match the admin's email domain. Inline error if not.
- On submit → creates `organization_integrations` row, status `pending`.

#### Step 2 — Install the bot
- CTA: *"Open Google Workspace Marketplace"* — opens marketplace listing in new tab.
- Instructions: *"Your Workspace admin should click 'Install' and choose 'Install for everyone in your organization' for guardianhha.com. This requires Google Workspace admin permissions."*
- *"Verify install"* button → backend attempts a test DM to the admin's own email. On success, status → `active`. On failure, *"Can't reach the bot yet. Make sure your Workspace admin has installed it."*

#### Step 3 — Configure cadence
- Checkboxes: 60 / 30 / 14 / 7 / 1 days before expiry + on expiry day. Default: 30/14/7/1 + expired.
- Toggle: *"Fall back to email if Chat delivery fails"* (default on).
- Toggle: *"Allow personal Google accounts (advanced)"* (default off, with red warning text about compliance).
- Save → writes `config` JSON.

### Screen C — Manage page (after setup)

```
Google Chat Integration                   [ Disable ]
─────────────────────────────────────────────────────
Workspace domain:  guardianhha.com   [verified ✓]
Status:            Active

Cadence
  ☑ 30 days before    ☑ 14 days before
  ☑ 7 days before     ☑ 1 day before
  ☑ On expiry day     ☐ 60 days before
  [ Save changes ]

Employee connection status                [ Refresh ]
─────────────────────────────────────────────────────
  ✓ Connected         12
  ⏳ Not connected     5    [ Send invite reminder ]
  ✉ Email-only        1    (personal Google account)

  Search employees ▼
  ┌────────────────────────────────────────────────┐
  │ Aniq Javed         developer2@guardianhha.com  │
  │                    ✓ Connected · 2 days ago    │
  ├────────────────────────────────────────────────┤
  │ Sarah Khan         sarah@guardianhha.com       │
  │                    ⏳ Not connected             │
  ├────────────────────────────────────────────────┤
  │ Tom Patel          tom.patel@gmail.com         │
  │                    ✉ Email-only (personal)     │
  └────────────────────────────────────────────────┘

Recent activity                          [ View all ]
─────────────────────────────────────────────────────
  Today  · 14 reminders sent (12 Chat, 2 email)
  Yest.  · 9 reminders sent (8 Chat, 1 email)
```

Disabling pauses dispatch for the org but keeps history.

## Phase 5 — Employee UI

Lives in the employee portal at `My Profile → Notifications`.

Four states the page can be in:

### State 1 — Org hasn't enabled Chat yet
```
Notifications

Email reminders                  ☑ Enabled
  License, TB report, and other document expiration alerts
  will be sent to:  aniq@guardianhha.com

Google Chat reminders            (Not available)
  Your organization hasn't enabled Google Chat. Contact
  your admin if you'd like to receive reminders here.
```

### State 2 — Org enabled, employee not connected (work email)
```
Notifications

Email reminders                  ☑ Enabled
  → aniq@guardianhha.com

Google Chat reminders            ⏳ Not connected
  ┌──────────────────────────────────────────────┐
  │ Connect in 3 steps:                           │
  │  1. Open Google Chat → [open chat.google.com] │
  │  2. Search "HomeHealth Reminders" → click Add │
  │  3. Send the bot any message (just say hi)   │
  │                                                │
  │ We'll detect it automatically and confirm     │
  │ here.                                          │
  └──────────────────────────────────────────────┘
  [ I added the bot, check now ]
```

The "check now" button polls the connection status. v2: long-poll or websocket so the UI updates the moment the bot's webhook fires.

### State 3 — Connected
```
Notifications

Email reminders                  ☑ Enabled
  → aniq@guardianhha.com

Google Chat reminders            ✓ Connected
  Connected on Apr 28, 2026
  Reminders are sent to your Google Chat as DMs.
  [ Send test reminder ]      [ Disconnect ]
```

### State 4 — Personal Gmail employee
```
Google Chat reminders            (Not available)
  Chat reminders are only available for accounts on
  your organization's Google Workspace (@guardianhha.com).
  You'll continue to receive reminders by email.
```

## Phase 6 — Marketplace publication

Run in parallel with Phases 1-5. Five sub-stages, sequenced. Detailed checklist in the plan doc under module 18:

1. **Pre-submission preparation** — privacy policy + terms covering Chat data, ~2 min demo video, listing description + screenshots, support contact, CASA review if required.
2. **Production GCP project (module 2)** — created under HomeHealth's own Workspace tenant (not Guardian's, where dev currently lives). Mirror dev Chat app config; service account JSON into prod secrets.
3. **OAuth verification** — submit via OAuth consent screen → review → respond to feedback (multiple weeks of back-and-forth typical).
4. **Marketplace listing creation** — listing assets uploaded via Marketplace SDK, distribution scope chosen (public vs. specific Workspace domains for staged rollout), separate Marketplace review queue.
5. **Post-approval flip** — set `GOOGLE_CHAT_ADMIN_INSTALL_URL` in prod env to the Marketplace direct-install URL (the response field `install_url` on `GET /v1/api/organizations/:orgId/integrations/google-chat` automatically picks it up — no frontend code change at flip-day). Switch Chat API visibility from allowlist to "public listing" or "available to everyone in domain." Optionally ship F8 (auto-install detection webhook) so the "Verify install" manual click goes away. **Also unblocks at this milestone:** auto-removal of the bot from the user's Chat on disconnect (`chat.spaces.members.delete` on DMs is gated by "administrator approval" pre-Marketplace; once the bot is published + domain-installed, the existing `leaveSpace` call in `EmployeeNotificationsService.disconnectChat` starts succeeding and the manual-removal copy on the disconnect confirmation can drop). And tier 3 zero-click connect (F2) starts being possible.

Until Marketplace approval, dev/test against the home Workspace tenant and one pilot customer by whitelisting their domain in the Chat API config's "Available to specific people and groups" setting.

## Local dev setup

Google Chat needs a public HTTPS URL to deliver webhook events. We tunnel localhost via ngrok.

### Daily workflow

```bash
# 1. Start the NestJS backend (if not already running)
npm run start:dev          # listens on port 8000

# 2. In a separate terminal, start the ngrok tunnel
ngrok http 8000

# 3. Copy the https://...ngrok-free.dev URL from the ngrok output (under "Forwarding")

# 4. Paste it (with /webhooks/google-chat/events appended) into:
#    Google Cloud Console → Chat API → Configuration → HTTP endpoint URL → Save
```

Order matters — backend first, then ngrok.

### Useful commands

```bash
pgrep ngrok && echo "running" || echo "stopped"   # is ngrok up?
open http://127.0.0.1:4040                        # ngrok request inspector (live req/res view)
pkill ngrok                                        # stop ngrok
```

### One-time: reserve a static ngrok domain (recommended)

The free random URL changes every restart, which means updating Google Console every time. Fix it once:

1. Visit https://dashboard.ngrok.com/domains → click **+ New Domain** → ngrok generates a free static domain like `homehealth-dev.ngrok-free.app`.
2. Start ngrok with that domain pinned:
   ```bash
   ngrok http --url=homehealth-dev.ngrok-free.app 8000
   ```
3. Set the Google Console URL to `https://homehealth-dev.ngrok-free.app/webhooks/google-chat/events` **once** and never touch it again.

Optional zsh alias:
```bash
alias hh-tunnel='ngrok http --url=homehealth-dev.ngrok-free.app 8000'
```

### Quick round-trip test

After ngrok is up and the URL is set in Google Console:

1. From `developer2@guardianhha.com`'s Google Chat, click **New chat** → search `HomeHealth Reminders` → add the bot → send any message.
2. Expect the bot reply: *"Hi {your name}, you're connected to HomeHealth Reminders…"*
3. NestJS terminal logs `Received Google Chat event: ADDED_TO_SPACE` plus the full payload.
4. Optional: open http://127.0.0.1:4040 to inspect the request body Google sent.

If the bot doesn't appear in Chat search, verify:
- You're logged into the whitelisted Google account (check the avatar in the top-right; URL `u/N` indicates which account).
- The "Build this Chat app as a Workspace add-on" box is **unchecked** in the Chat API config.
- Visibility includes the email you're testing with (Google notes changes can take up to 24 hours, but it's usually minutes).

## MVP cut

### Drop from v1
- `notification_preferences` table — single global toggle per channel is fine.
- Cards v2 with buttons — plain text DM ships faster.
- Org admin's "Recent activity" panel — log table is enough; UI later.
- Per-employee "send test reminder" button.
- "Send invite reminder" bulk action.

### Must ship for v1
- The 3 core tables.
- Bot webhook for ADDED_TO_SPACE / REMOVED_FROM_SPACE.
- Daily cron + dispatcher + Chat & email channels.
- Org setup wizard (domain → install → cadence).
- Employee Notifications page (states 1–4).
- Email fallback.

## Timeline

Realistic estimate for one mid-level engineer:

| Phase | Work | Duration |
|-------|------|----------|
| 0 | Google Cloud setup + Marketplace submission | 0.5 day to start; ~3-6 weeks of Google review running in parallel |
| 1 | Data model + module scaffolding | 2-3 days |
| 2 | Bot webhook + linking | 2-3 days |
| 3 | Dispatcher + cron + channels + email fallback | 4-5 days |
| 4 | Org admin UI | 4-5 days |
| 5 | Employee UI | 2-3 days |
| — | Buffer + QA | 3-4 days |

**≈ 3.5 weeks of dev**, gated on Marketplace approval before onboarding a second customer.

## Open design questions

1. **Cadence defaults** — 30/14/7/1 + expired is proposed. Confirm.
2. **Reminder message wording** — needs a copy pass before v1 ships.
3. **Who can enable the integration** — only org owners, or any admin role? Pin down before building Screen B.
4. **Cross-tenant employees** — can a single person work for two HH orgs simultaneously? If yes, `user_chat_connections` may need to be scoped per `(user_id, org_id)` instead of per `user_id`.
5. **Rate-limit / fairness** — the Chat API quota is per-app, shared across all tenants. For v1 a simple BullMQ rate-limit on the dispatch queue is enough; per-tenant fairness can come later.
6. **Time zones** — daily cron at 8am UTC for v1; per-org/per-employee local-time delivery in v2.
