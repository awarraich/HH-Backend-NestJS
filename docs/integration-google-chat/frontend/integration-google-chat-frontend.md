# Google Chat Integration — Frontend Implementation Guide

This document is a self-contained handoff for the frontend developer building the UI surfaces for the Google Chat reminder integration. The backend is fully built and verified end-to-end; this guide tells you exactly what to consume, what screens to build, and what the user-visible copy should say.

For the architectural context (multi-tenant model, why Chat-only-for-Workspace, etc.), skim [../backend/integration-google-chat.md](../backend/integration-google-chat.md). You don't need to read it cover-to-cover — the pieces that affect frontend behavior are summarized inline below.

## Table of contents

- [The product in one paragraph](#the-product-in-one-paragraph)
- [Two surfaces to build](#two-surfaces-to-build)
- [Backend status (what works now)](#backend-status-what-works-now)
- [Org admin: Settings → Integrations → Google Chat](#org-admin-settings--integrations--google-chat)
- [Employee: My Profile → Notifications](#employee-my-profile--notifications)
- [API contracts](#api-contracts)
- [The "Connect Google Chat" button — three tiers](#the-connect-google-chat-button--three-tiers)
- [State management & polling](#state-management--polling)
- [Copy & wording (canonical)](#copy--wording-canonical)
- [Design system & primitives](#design-system--primitives)
- [Suggested route & file layout](#suggested-route--file-layout)
- [Edge cases & error handling](#edge-cases--error-handling)
- [Testing checklist](#testing-checklist)
- [Future improvements (post-Marketplace publication)](#future-improvements-post-marketplace-publication)
- [Open questions for product](#open-questions-for-product)

## The product in one paragraph

Customer organizations enable a HomeHealth-built bot to deliver document-expiration reminders (license, TB report, in-service training certifications) to their employees as direct messages in Google Chat — falling back to email when Chat isn't available. There are two human surfaces to expose: an **org-admin setup + management page**, and an **employee notifications page**. The whole reminder pipeline (cron → queue → dispatcher → Chat or email) runs server-side; the frontend's job is letting humans turn it on, configure it, and see status.

## Two surfaces to build

| Surface | Path (suggested) | Who uses it | What they do |
|---|---|---|---|
| Org admin | `Settings → Integrations → Google Chat` | The org **owner**, OR an ACTIVE staff member with role `HR` / `MANAGER` | Enable, configure cadence, monitor employee connection status, disable |
| Employee | `My Profile → Notifications` | Anyone with org membership — owner, staff, or regular employee | See their connection status; connect/disconnect their own Chat |

These are independent. Build them in either order. The org-admin side is more work because it has a wizard.

## Backend status (what works now)

| What | Status | API surface |
|---|---|---|
| Org admin endpoints | ✅ Live | `/v1/api/organizations/:organizationId/integrations/google-chat/*` (module 13 in the plan) |
| Employee endpoints | ✅ Live | `/v1/api/me/notifications/*` (module 16) |
| Reminder pipeline | ✅ Live | Daily cron → BullMQ queue → dispatcher → Chat/email (modules 5–12) |
| Bot webhook events | ✅ Live | Bot DMs the employee on `ADDED_TO_SPACE`; flips `user_chat_connections` row |

You can build both the org-admin and employee UIs against the live backend today.

## Org admin: Settings → Integrations → Google Chat

This is a three-step setup wizard plus a manage page. The integration's `status` field on the backend (`pending` | `active` | `disabled` | not-yet-created) determines which view to render.

### Entry point — Integrations list

Generic settings → integrations index. Show one card per supported integration (currently just Google Chat).

```
┌──────────────────────────────────────────────────┐
│ 📨 Google Chat                                    │
│ Send document expiration reminders to your        │
│ employees via Google Chat DMs.                    │
│                                                    │
│ Status: <integration status badge>      [<CTA>]   │
└──────────────────────────────────────────────────┘
```

CTA varies by state:
- No integration row yet → **Set up**
- `status = pending` → **Continue setup**
- `status = active` → **Manage** (badge: ✓ Active · X of Y employees connected)
- `status = disabled` → **Re-enable**

Use `<StatusBadge tone>` for the status indicator (per the [employee-portal-ui skill](../../../../js-code/HH-Frontend/.claude/skills/employee-portal-ui/SKILL.md)): teal for active, slate for not-set-up, amber for pending, slate for disabled.

### Wizard — Step 1: Workspace domain

Triggered by **Set up** or **Continue setup** when `integration === null` or `status === 'pending'` and `workspace_domain` is missing.

```
┌──────────────────────────────────────────────────┐
│ Step 1 of 3 — Confirm your Google Workspace      │
│                                                    │
│ What's your organization's Google Workspace      │
│ domain?                                            │
│                                                    │
│ ┌──────────────────────────────────────────────┐  │
│ │ guardianhha.com                              │  │
│ └──────────────────────────────────────────────┘  │
│ This must match your own email address           │
│ (developer2@guardianhha.com).                     │
│                                                    │
│         [ Cancel ]   [ Continue → ]              │
└──────────────────────────────────────────────────┘
```

- Pre-fill the input with the domain from the logged-in user's email (`user.email.split('@')[1]`).
- Submit calls `POST /enable` with `{workspace_domain}`.
- **Server validates** the domain matches the actor's email domain and rejects with 400 + a clear error message if not. Surface the message inline; don't suppress it.
- On success → advance to step 2.

### Wizard — Step 2: Install the bot

Triggered when `status === 'pending'` after step 1.

```
┌──────────────────────────────────────────────────┐
│ Step 2 of 3 — Install the bot                    │
│                                                    │
│ Your Google Workspace admin needs to install the  │
│ HomeHealth Reminders bot for guardianhha.com.    │
│                                                    │
│ 1.  [ Open Google Workspace Marketplace ↗ ]      │
│ 2.  Have your admin click "Install" → choose     │
│     "Install for everyone in your organization". │
│ 3.  Come back here and click Verify.             │
│                                                    │
│ ⚠ This requires Google Workspace admin           │
│   permissions. If you're not the admin, send     │
│   them this link.                                  │
│                                                    │
│         [ Back ]   [ Verify install → ]          │
└──────────────────────────────────────────────────┘
```

- The "Open Marketplace" button opens `install_url` from the `GET /` response in a new tab. **Don't construct the URL yourself** — read whatever the backend returned. Pre-Marketplace this is a Chat user-add deep link (so the admin can add the bot to their own Chat as a stand-in for domain install); post-Marketplace it's the real admin install URL on `admin.google.com`. Backend env-flag swap, zero frontend change at flip-day.
- **Verify** button calls `POST /verify`. The server attempts to send a real test DM to the *actor's* Chat. On 200 → status becomes `active` → advance to step 3.
- If the actor hasn't added the bot to their own Chat yet, the server returns 400 with a message that says exactly that. Show the message inline; the user needs to add the bot first then click Verify again.
- **Future (post-Marketplace, F8 in backend plan):** the manual Verify click can be replaced by an auto-polling spinner that watches for the install completion webhook the Chat API fires when a Workspace admin completes domain install. Backend ships F8 → frontend swaps the Verify button for a polling state. Until F8 ships, keep the manual button.

### Wizard — Step 3: Configure cadence

Triggered when `status === 'active'` for the first time (no `config` set yet).

```
┌──────────────────────────────────────────────────┐
│ Step 3 of 3 — When to remind employees           │
│                                                    │
│ Send reminders before a document expires:         │
│   ☐ 60 days before                                │
│   ☑ 30 days before                                │
│   ☑ 14 days before                                │
│   ☑ 7 days before                                │
│   ☑ 1 day before                                 │
│   ☑ On the day it expires                         │
│                                                    │
│ Delivery rules                                    │
│   ☑ Fall back to email if Chat delivery fails    │
│   ☐ Allow personal Google accounts (advanced)    │
│     ⚠ Personal accounts can't be controlled by    │
│       your IT — recommended only if you           │
│       understand the compliance trade-off.         │
│                                                    │
│         [ Back ]   [ Save settings ]              │
└──────────────────────────────────────────────────┘
```

- Default checked: 30 / 14 / 7 / 1 days + on-expiry-day. Send `cadence: ['30d', '14d', '7d', '1d', 'expired']` in the PATCH body. Allowed kinds: `60d`, `30d`, `14d`, `7d`, `1d`, `expired`.
- "Allow personal Google accounts" toggle = `allow_personal_accounts: boolean` in config. Default off, with a real warning. Most orgs should keep this off.
- On save → `PATCH /config` → done with wizard → route to manage page.

### Manage page

Triggered when `integration.status === 'active'` and `config` is set.

```
┌──────────────────────────────────────────────────────────┐
│ Google Chat Integration                  [ Disable ⌄ ]   │
│ ───────────────────────────────────────────────────────  │
│                                                            │
│ Workspace domain  guardianhha.com    [verified ✓]        │
│ Status            ✓ Active                                │
│                                                            │
│ Cadence                                       [ Edit ]    │
│   30 days · 14 days · 7 days · 1 day · expired           │
│                                                            │
│ Employee connection status                  [ Refresh ]   │
│   ✓ Connected         12                                   │
│   ⏳ Not connected      5    [Send invite reminder]       │
│   ✉ Email-only         1    Personal Google accounts     │
│   ✗ Revoked            0                                   │
│                                                            │
│   Search employees ↓                                       │
│   ┌────────────────────────────────────────────────────┐  │
│   │ Aniq Javed         developer2@guardianhha.com      │  │
│   │                    ✓ Connected · 2 days ago        │  │
│   ├────────────────────────────────────────────────────┤  │
│   │ Sarah Khan         sarah@guardianhha.com           │  │
│   │                    ⏳ Not connected                 │  │
│   ├────────────────────────────────────────────────────┤  │
│   │ Tom Patel          tom.patel@gmail.com             │  │
│   │                    ✉ Email-only (personal)         │  │
│   └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

Sources:
- Top section (domain, status, cadence): `GET /` returns the full integration row.
- Employee list: `GET /employees` returns `{employees: [...], summary: {connected, not_connected, email_only, revoked}}`. Use the summary directly for the rollup counts.

Per-row actions are deferred to v2 (F6/F7 in the backend plan): "Send invite reminder" and per-employee test reminder. For v1, just render the list + summary.

**Disable** is in a kebab/dropdown to discourage accidental clicks. Confirms with a small modal: *"Disable Google Chat reminders? Employees will stop receiving Chat DMs immediately. Email reminders continue. You can re-enable any time."* On confirm → `POST /disable`.

**Edit cadence** opens an inline edit form (same checkboxes as Step 3 of the wizard) → `PATCH /config`.

## Employee: My Profile → Notifications

The employee page renders one of **four states** based on the org integration status + the employee's own connection status. Backend (module 16) is live — see [API contracts](#employee-api-live) below.

### State 1 — Org hasn't enabled Chat yet

```
Notifications

Email reminders                   ☑ Enabled
  License, TB report, and other document
  expiration alerts will be sent to:
  aniq@guardianhha.com

Google Chat reminders             (Not available)
  Your organization hasn't enabled Google Chat.
  Contact your admin if you'd like to receive
  reminders here.
```

Rendered when the org has no `organization_integrations` row OR `status !== 'active'`.

### State 2 — Org enabled, employee not connected (work email)

```
Notifications

Email reminders                   ☑ Enabled
  → aniq@guardianhha.com

Google Chat reminders             ⏳ Not connected
  ┌──────────────────────────────────────────┐
  │ Connect to receive expiration            │
  │ reminders in Chat.                        │
  │                                            │
  │   [ Connect Google Chat ]  ← see Tiers   │
  │                                            │
  │ This will open Google Chat with the      │
  │ HomeHealth Reminders bot. Click "Add"    │
  │ in Chat and we'll detect it.             │
  └──────────────────────────────────────────┘
```

The **Connect Google Chat** button has three behaviors depending on environment — see [Tier 1 / 2 / 3](#the-connect-google-chat-button--three-tiers).

After the user clicks (or while waiting for them to add the bot in Chat), the page should poll `GET /api/me/notifications` every ~5 seconds until `connection.status === 'connected'`, then transition to state 3 without requiring a manual refresh.

### State 3 — Connected

```
Notifications

Email reminders                   ☑ Enabled
  → aniq@guardianhha.com

Google Chat reminders             ✓ Connected
  Connected on Apr 28, 2026
  Reminders are sent to your Google Chat
  as direct messages.

  [ Send test reminder ]   [ Disconnect ]
```

`Send test reminder` is deferred (F7); ship without it for v1 if needed. `Disconnect` calls a backend endpoint that flips the connection to `revoked` and instructs the user to also remove the bot from their Chat for full disconnect.

### State 4 — Personal Gmail / domain mismatch

```
Notifications

Email reminders                   ☑ Enabled
  → aniq@gmail.com

Google Chat reminders             (Not available)
  Chat reminders are only available for
  accounts on your organization's Google
  Workspace (@guardianhha.com).

  You'll continue to receive reminders by
  email. To enable Chat, ask your admin
  to provision a @guardianhha.com account.
```

Rendered when the employee's email domain doesn't match the org's `workspace_domain`. The backend already detects this and creates the connection row with `chat_eligible=false` even if the employee adds the bot — so this state is determined from the connection's `chat_eligible` flag (or from the email-domain check pre-connection).

## API contracts

Base path for both surfaces: `/v1/api`.

### Response envelope (read this first)

**Every successful response is wrapped** in the project-standard envelope:

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": { ...the payload shown below },
  "timestamp": "2026-05-04T..."
}
```

Your API client should unwrap `data` before passing to UI code. The example response shapes documented below show **only the `data` payload** — they're what you'd see at `response.data.data` if you're using axios, or after `await res.json().then(r => r.data)`.

**Errors are NOT wrapped** — they use NestJS's standard error envelope, which is what's returned with non-2xx status codes:

```json
{
  "message": "Human-readable error message",
  "error": "Bad Request",
  "statusCode": 400
}
```

So your error handler should read `error.response.data.message` (axios) or `(await res.json()).message` (fetch). The same shape applies to 400/403/404/500.

### Auth

All endpoints require a JWT in `Authorization: Bearer <token>`. Employee endpoints are scoped via the `sub` claim (the user's id) and resolve the user's org via three membership signals (union): owner of the org, ACTIVE staff member, or ACTIVE employee. Org admin endpoints accept either the **org owner** or an **ACTIVE staff member with `HR` or `MANAGER` role** — owners don't need a staff row to manage their own integration.

### Org admin endpoints (live)

All under `/v1/api/organizations/:organizationId/integrations/google-chat`.

#### `GET /` — read integration
```json
// 200 (data payload, after unwrapping the response envelope)
{
  "integration": null,        // or the integration row, see below
  "install_url": "https://..."  // see "install_url" notes below
}

// integration shape when non-null:
// {
//   "id": "uuid",
//   "org_id": "uuid",
//   "provider": "google_chat",
//   "status": "pending" | "active" | "disabled",
//   "workspace_domain": "guardianhha.com",
//   "config": { "cadence": ["30d","14d","7d","1d","expired"], "fallback_to_email": true, "allow_personal_accounts": false } | null,
//   "enabled_by_user_id": "uuid",
//   "enabled_at": "2026-05-01T...",
//   "verified_at": "2026-05-01T...",
//   "disabled_at": null,
//   "created_at": "...", "updated_at": "..."
// }
```

**`install_url` field:** the URL that the wizard's "Install bot" button on step 2 should open in a new tab. **Always read this from the response — don't construct it yourself.** Pre-Marketplace it returns the Chat user-add deep link (`https://chat.google.com/u/0/app/<APP_ID>`). Post-Marketplace publication, the backend swaps it server-side to the Marketplace admin-install URL (`https://admin.google.com/ac/marketplace/app/.../install` or similar) without any frontend change.

#### `POST /enable` — start or restart setup
```json
// Request
{ "workspace_domain": "guardianhha.com" }

// 200 → returns integration (status = 'pending', or 'active' if previously verified)
// 400 → workspace_domain doesn't match the actor's email domain
```

#### `POST /verify` — send verification DM
```json
// Request: empty body

// 200 → returns integration (status = 'active', verified_at populated)
// 400 → actor hasn't added the bot to their own Chat yet (message includes how-to)
// 400 → bot is unreachable / Chat API failure (message includes underlying error)
```

#### `PATCH /config` — update cadence + flags
```json
// Request (all fields optional, server merges)
{
  "cadence": ["30d","14d","7d","1d","expired"],
  "fallback_to_email": true,
  "allow_personal_accounts": false
}

// 200 → returns integration with updated config
```

#### `POST /disable`
```json
// 200 → returns integration with status='disabled', disabled_at populated
```

#### `GET /employees`
```json
// 200
{
  "employees": [
    {
      "user_id": "uuid",
      "email": "developer2@guardianhha.com",
      "name": "Developer Two",
      "status": "connected" | "not_connected" | "email_only" | "revoked",
      "connected_at": "2026-05-01T..." | null
    }
  ],
  "summary": { "connected": 1, "not_connected": 0, "email_only": 0, "revoked": 0 }
}
```

<a id="employee-api-live"></a>
### Employee API (live)

All under `/v1/api/me/notifications`. Backend (module 16) is implemented and verified.

#### `GET /` — get current notification state
```json
// 200
{
  "email_destination": "developer2@guardianhha.com",
  "org_integration_status": "active" | "pending" | "disabled" | "not_enabled",
  "workspace_domain": "guardianhha.com" | null,
  "chat_connection": null,   // or:
  // {
  //   "status": "connected" | "revoked" | "pending",
  //   "chat_eligible": true,
  //   "connected_at": "2026-05-01T..." | null
  // }
}
```

The frontend derives the State 1–4 view from this single payload:

| Condition | View state |
|---|---|
| `org_integration_status !== 'active'` | State 1 (org disabled) |
| `chat_connection === null` AND email domain matches `workspace_domain` | State 2 (connect-prompt) |
| `chat_connection.status === 'connected'` AND `chat_eligible === true` | State 3 (connected) |
| `chat_connection.chat_eligible === false` (or email domain doesn't match) | State 4 (personal-Gmail) |

#### `POST /chat/connect` — initiate connect (Tier 2 / Tier 3)
```json
// Request: empty body

// Tier 2 (dev / pre-Marketplace, current default) — 200
{
  "tier": "deep_link",
  "url": "https://chat.google.com/u/0/app/128879610173"
}

// Tier 3 (post-Marketplace, post-domain-install — not yet emitted by backend, future) — 200
{
  "tier": "zero_click",
  "connection": { "status": "connected", "chat_eligible": true, "connected_at": "..." }
}

// 400 — org integration not active, OR personal-Gmail domain mismatch
// (NestJS standard error envelope)
{ "message": "...", "error": "Bad Request", "statusCode": 400 }
```

The frontend should switch on `tier` to decide whether to open the URL in a new tab (Tier 2) or skip straight to State 3 (Tier 3). The 400 message is human-readable — surface it inline.

#### `POST /chat/disconnect`
```json
// 200 — flips connection to status='revoked'; the response echoes the connection's current shape
{
  "connection": {
    "status": "revoked",
    "chat_eligible": true,
    "connected_at": "2026-05-01T..."   // preserved for audit
  }
}

// 404 — no connection to disconnect
{ "message": "No Chat connection to disconnect.", "error": "Not Found", "statusCode": 404 }
```

After disconnect, the backend **attempts** to remove the bot from the user's Chat via `chat.spaces.members.delete`, then marks the DB row revoked. **Pre-Marketplace publication, the Chat-side removal will fail** — Google blocks `members.delete` on DM spaces unless the Chat app is Marketplace-published and the customer's Workspace admin has domain-installed it. The error is logged calmly (not as a warning) and the disconnect still completes on the HomeHealth side. **For now, the disconnect confirmation should tell the user to also remove the bot manually from their Chat.** Once module 18 ships and customer admins start domain-installing the bot, the Chat-side cleanup will start working automatically with no frontend code change.

#### `POST /chat/test-reminder` (deferred — F7)
Sends a sample reminder to the user's connected Chat. Returns 400 if not connected. **Skip for v1.**

## The "Connect Google Chat" button — three tiers

The same UI button has three different behaviors depending on the deployment state. Backend's `POST /chat/connect` returns which tier to use; the frontend just follows the response.

### Tier 1 — Manual (always works, but worst UX)

Employee opens Chat themselves, searches "HomeHealth Reminders", adds the bot. **Don't surface this as a button — it's only the fallback if the user can't use Tier 2/3.**

### Tier 2 — Deep link button

Available **today** in dev and post-Marketplace publication. Backend returns `{tier: "deep_link", url: "https://chat.google.com/u/0/app/<APP_ID>"}`. Frontend:

```ts
window.open(response.url, '_blank', 'noopener,noreferrer');
// then start polling GET /api/me/notifications every 5s
```

The user clicks Add in Chat, the bot fires `ADDED_TO_SPACE` to the backend, the backend creates the `user_chat_connections` row, the next poll picks it up, the page transitions to State 3.

### Tier 3 — Zero-click

Available **post-Marketplace + after Workspace admin installs for the domain**. Backend returns `{tier: "zero_click", connection: {...}}` — the connection is already created server-side. Frontend just transitions to State 3 immediately, no Chat tab opens. The user gets a welcome DM in their Chat from the bot.

**The button click handler doesn't need to know which tier**: it just calls the endpoint and reacts to the `tier` field. The backend chooses based on org config and Marketplace state.

## State management & polling

### Org admin

- Static fetches: `GET /` and `GET /employees` on page mount.
- Optimistic updates after PATCH/POST: backend always returns the updated row, so just replace local state with the response.
- No polling needed.

### Employee

- Initial fetch: `GET /api/me/notifications` on page mount.
- **Poll while waiting for connection.** When the user clicks Connect (Tier 2), start polling every 5 seconds. Stop polling when:
  - `chat_connection.status === 'connected'` → transition to State 3.
  - User leaves the page.
  - Polling has been running for 5 minutes → stop and show: *"Still not connected? Open Google Chat and make sure you added the bot. [Try again]"*.
- Replace polling with WebSocket / Server-Sent Events in v2 if/when the backend exposes a real-time channel.

## Copy & wording (canonical)

Single source of truth — keep these strings consistent across both surfaces. If product wants to tweak, edit them here first and propagate.

### Org admin

| Place | Copy |
|---|---|
| Setup wizard step 1 title | Confirm your Google Workspace |
| Domain mismatch error | (server-supplied) "Workspace domain (X) must match your email domain (Y)…" |
| Step 2 title | Install the bot |
| Step 2 admin-required warning | This requires Google Workspace admin permissions. |
| Verify button label | Verify install |
| Verify failure | (server-supplied) — render verbatim |
| Step 3 title | When to remind employees |
| Step 3 personal-accounts warning | Personal accounts can't be controlled by your IT — recommended only if you understand the compliance trade-off. |
| Manage page status — active | Active |
| Manage page status — disabled | Disabled |
| Disable confirmation | Disable Google Chat reminders? Employees will stop receiving Chat DMs immediately. Email reminders continue. You can re-enable any time. |
| Employee row — connected | ✓ Connected · {relative time} |
| Employee row — not connected | ⏳ Not connected |
| Employee row — email only | ✉ Email-only (personal) |

### Employee

| Place | Copy |
|---|---|
| State 1 unavailable note | Your organization hasn't enabled Google Chat. Contact your admin if you'd like to receive reminders here. |
| State 2 connect prompt | Connect to receive expiration reminders in Chat. |
| State 2 connect button | Connect Google Chat |
| State 2 helper after click | Opening Google Chat… click **Add** when the bot appears. We'll detect it automatically. |
| State 2 polling-timeout | Still not connected? Open Google Chat and make sure you added the bot. |
| State 3 confirmation | Reminders are sent to your Google Chat as direct messages. |
| State 3 connected timestamp | Connected on {date} |
| State 4 personal-account note | Chat reminders are only available for accounts on your organization's Google Workspace ({workspace_domain}). You'll continue to receive reminders by email. To enable Chat, ask your admin to provision a {workspace_domain} account. |
| Disconnect confirmation (pre-Marketplace) | Disconnect Google Chat? You'll stop receiving Chat DMs and fall back to email. To fully remove the bot, also remove it from your Chat (search "HomeHealth Reminders" in Chat → kebab menu → Remove). |
| Disconnect confirmation (post-Marketplace, future) | Disconnect Google Chat? You'll stop receiving Chat DMs and fall back to email. The bot will be removed from your Chat automatically. |

## Design system & primitives

This integration's UI must use the existing `employee-portal-ui` design system. Cross-reference: [HH-Frontend/.claude/skills/employee-portal-ui/SKILL.md](../../../../js-code/HH-Frontend/.claude/skills/employee-portal-ui/SKILL.md).

Key primitives to use (do not hand-roll):

- **`<Button>`** — `primary` for main CTAs (Verify, Save, Connect Google Chat), `secondary` for navigation (Cancel, Back), `destructive` for Disconnect/Disable, `ghost` for kebab actions, `accent` is fine for the "Open Marketplace" CTA.
- **`<Card>`** — for the integration card on the Settings → Integrations index, the wizard panels, and the employee state-2 connect prompt block.
- **`<StatusBadge tone>`** — every status indicator. `tone="success"` for connected/active, `tone="warning"` for pending/not-connected, `tone="error"` for revoked/disabled, `tone="neutral"` for email-only/not-enabled.
- **`<EmptyState>`** — if a customer org's employee list is empty (no `organization_staff` rows), render the centered variant with a friendly message.
- **Page structure** — wrap in the standard heading-row → toolbar → content pattern; `space-y-5` for sections.

Color rules from the skill (do not deviate):
- Primary CTA = teal-600.
- Status colors: teal=connected, amber=not-connected, red=revoked, slate=neutral/email-only.
- No gradients on this surface. No orange. No green (use teal for active).

Iconography: `lucide-react` only. Suggested icons:
- `MessageSquare` or `MessageCircle` for the Google Chat integration card header.
- `CheckCircle2` for connected status.
- `Clock` for pending/not-connected.
- `Mail` for email-only.
- `XCircle` for revoked.
- `ExternalLink` next to the "Open Marketplace" / "Open Google Chat" buttons.

## Suggested route & file layout

This is a suggestion for the frontend's structure — adapt to whatever conventions HH-Frontend already uses.

```
src/features/admin-settings/integrations/google-chat/        ← org admin
  IntegrationsIndexPage.tsx               // entry: list of integrations
  GoogleChatSetupWizard.tsx               // 3-step wizard
  GoogleChatManagePage.tsx                // post-setup management
  hooks/
    useGoogleChatIntegration.ts           // GET /, mutations
    useGoogleChatEmployees.ts             // GET /employees
  components/
    DomainStep.tsx
    InstallStep.tsx
    CadenceStep.tsx
    EmployeeConnectionList.tsx
    DisableConfirmDialog.tsx

src/features/employee/notifications/                          ← employee
  NotificationsPage.tsx                   // top-level state machine
  components/
    State1OrgDisabled.tsx
    State2NotConnected.tsx
    State3Connected.tsx
    State4PersonalAccount.tsx
  hooks/
    useEmployeeNotifications.ts           // GET /me/notifications + polling
    useChatConnect.ts                     // POST /me/notifications/chat/connect
```

## Edge cases & error handling

| Case | Handling |
|---|---|
| User loads admin page but isn't owner / HR / MANAGER | Backend returns 403; show "You don't have access to this integration. Contact your org admin." |
| Network error on a mutation | Toast: "Couldn't reach the server. Try again." Don't silently roll back optimistic UI; revert to last-known-good state. |
| Verify fails because bot wasn't added | Server returns 400 with the helpful message; render the message inline near the Verify button, don't toast it (it's actionable, not transient). |
| Employee's email domain matches org workspace domain but they haven't added the bot | State 2. Show the deep-link button. |
| Employee adds the bot via Chat, then immediately reloads HH | The polling on State 2 catches it; OR the page-mount fetch returns `connection.status='connected'` and goes straight to State 3. Both paths work. |
| Org admin disables the integration | Active employees stay in their connected state in the DB but the dispatcher won't pick up new reminders for that org. Employee UI doesn't need to do anything different — it'll show whatever state the DB reports (still connected, just won't receive new reminders). |
| User in two orgs (cross-tenant employee) | Open question — backend's `GET /me/notifications` will need to either return all org integrations or pick one. Ask product before building this branch. (See [open question #1](#open-questions-for-product).) |
| Bot DM fails to deliver during verify | Server returns 400 with the underlying Chat API error; surface verbatim. The user should refresh Chat and try again. |
| Polling timeout (5 min) on State 2 | Stop polling; show retry CTA. |
| Personal Gmail user clicks Connect anyway | Backend's `POST /chat/connect` returns 400; show State 4 contents inline as the error explanation. |

## Testing checklist

Before shipping, exercise each of these manually:

**Org admin flow**
- [ ] Navigate to Settings → Integrations as an HR user → see Google Chat card with "Set up" CTA.
- [ ] Click Set up → land in wizard step 1 with email-domain prefilled.
- [ ] Submit wrong domain → inline error, stay on step 1.
- [ ] Submit correct domain → advance to step 2.
- [ ] Click Verify before adding the bot → inline error explaining how to add it.
- [ ] Add bot in Chat (separate window) → click Verify → advance to step 3.
- [ ] Toggle a few cadence boxes, save → land on manage page.
- [ ] Manage page shows status=Active, cadence chips, and the employee list with summary.
- [ ] Click "Disable" → confirm → integration shows Disabled. Re-enable works.
- [ ] As a non-HR user, navigate to the admin page → 403 / access-denied screen.

**Employee flow**
- [ ] State 1: Visit notifications page when org hasn't enabled → see unavailable copy.
- [ ] State 2: Visit when org enabled but not connected → see connect button. Click it → Chat tab opens with bot. Add bot → page transitions to State 3 within ~5 seconds.
- [ ] State 3: Visit when connected → see "Connected on {date}". Click Disconnect → confirm → State transitions back (effectively State 2 since connection is now revoked).
- [ ] State 4: Visit as a user with `@gmail.com` (or any domain ≠ workspace) → see personal-account explanation.
- [ ] Polling timeout: click Connect → don't add bot for 5 min → see "Still not connected?" message.

**Visual / a11y**
- [ ] All buttons reachable by keyboard (tab order is logical).
- [ ] Status badges have accessible labels (aria-label) — color alone shouldn't carry meaning.
- [ ] Wizard step indicator has correct aria-current.
- [ ] Confirmation modals are dismissible by Escape.
- [ ] Mobile breakpoint: wizard panels stack cleanly; manage page tables scroll.

## Future improvements (post-Marketplace publication)

These are landing on the backend later — the frontend either gets them "for free" (no UI changes needed) or with small additive changes. Calling them out so you don't bake assumptions that block them.

### Free changes (no frontend code needed)

- **Direct admin-install URL.** Once the bot is published to the Google Workspace Marketplace, the backend will swap `install_url` (returned from `GET /`) from the current Chat user-add deep link to a direct admin-install URL on `admin.google.com`. **Render whatever URL the backend returns** — don't hardcode the Chat URL pattern. As long as you read `install_url` from the response, the wizard step 2 button automatically does the right thing post-flip.
- **Tier 3 zero-click connect for employees.** `POST /me/notifications/chat/connect` will start returning `{tier: 'zero_click', connection: {...}}` once domain-install is in place. The frontend already needs to switch on `tier` per the [Tiers section](#the-connect-google-chat-button--three-tiers); when it's `zero_click`, skip opening a tab and transition straight to State 3.

### Small additive change (~half day frontend)

- **Auto-detect install completion (F8 in backend plan).** When the backend webhook starts auto-flipping `organization_integrations.status='active'` after a Workspace admin completes domain install on Google's side, the wizard step 2 should:
  1. Replace the "Verify install" button with a polling spinner ("Waiting for install confirmation from Google… click [Verify install] if you've installed the bot but this doesn't auto-detect within a minute").
  2. Poll `GET /` every ~3 seconds while in the "waiting" state.
  3. When `integration.status === 'active'` → auto-advance to step 3.
  4. Keep the manual "Verify install" button as a fallback (renamed to a small text link) for the case the webhook didn't fire.
  
  The backend lands the webhook handler first; the frontend change is on top of it. Wait until the backend dev says F8 is shipped before flipping the UI.

### Deferred / future-future

- **Per-org branding inside reminder DMs (F3).** Cards V2 messages with the customer org's logo and name in the card header (the bot identity stays "HomeHealth Reminders" — Google Chat doesn't allow per-tenant bot identities). No frontend impact unless the org-admin manage page surfaces customizing the org's logo for the bot to use; that'd be a small new section.
- **Per-employee "send test reminder" (F7).** State 3 button. Calls a backend endpoint that sends a sample reminder DM. ~1 hour frontend.
- **Bulk "send invite reminder" admin action (F6).** Manage-page button next to the "not connected" employee count.

## Open questions for product

These don't block v1 build, but pin them down before launch:

1. **Cross-tenant employees.** Can a HomeHealth user be staff at multiple orgs simultaneously? If yes, what does the employee Notifications page show — pick one, list all, or something else?
2. **Re-verification cadence.** Should the integration re-verify itself periodically (e.g. weekly), or stay verified until manually disabled?
3. **Disconnect message wording.** Backend tries to auto-remove the bot via `chat.spaces.members.delete`, but Google blocks this on DM spaces pre-Marketplace publication ("DMs are not supported for methods requiring app authentication with administrator approval"). For v1, the disconnect confirmation should tell the user to remove the bot manually. Post-Marketplace + domain-install, this starts working — flip the copy at the same time you flip `GOOGLE_CHAT_ADMIN_INSTALL_URL`.
4. **Employee admin override.** Can an org admin force-disconnect a specific employee from the manage page (e.g., when the employee leaves)? Backend can support this trivially; frontend would need a per-row action.

## Where this doc lives

- This file: [docs/integration-google-chat/frontend/integration-google-chat-frontend.md](.) — frontend handoff (you're reading it).
- [Backend design doc](../backend/integration-google-chat.md) — architecture, decisions, ASCII mockups, MVP cut.
- [Backend execution plan](../backend/integration-google-chat-plan.md) — module-by-module status, what's built, what remains.

When the frontend implementation gets going, log changes to *this* file (or a sibling `integration-google-chat-frontend-plan.md` if it grows) — don't backflow them into the backend doc.
