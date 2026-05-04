# Google Chat Scheduling Agent — Frontend Handoff

The agent's primary surface is **Google Chat itself** — most user interaction is in DMs with the bot, rendered via Card v2 payloads built server-side (see [`backend/agent-google-chat-bot-plan.md`](../backend/agent-google-chat-bot-plan.md), module M9). This doc covers the small set of **HH web frontend** touchpoints that surround that experience.

> **Cross-references.** The web frontend already has Google Chat integration screens for the notification module — see [`docs/integration-google-chat/frontend/integration-google-chat-frontend.md`](../../integration-google-chat/frontend/integration-google-chat-frontend.md). The agent reuses those entry points; this doc only describes additions/changes.

---

## 1. Surface map

| # | Surface | Audience | Status |
|---|---|---|---|
| FE1 | Org admin: scheduling-agent toggle on the existing Google Chat integration page | Org admin | ❌ Not started |
| FE2 | Org admin: usage & quota dashboard — per-employee message counts, total cost, quota status | Org admin | ❌ Not started |
| FE3 | Org admin: manual quota top-up action (Phase 14a) | Org admin | ❌ Not started |
| FE4 | Employee: notification preferences page — informational link/hint about the bot | Employee | ❌ Not started |
| FE5 | **(Future)** Org admin: paid-plan management UI — subscribe, change plan, view invoices | Org admin | 💤 Deferred (Phase 14b) |
| FE6 | **(Future)** Employee: in-card "request more messages" CTA | Employee | 💤 Deferred (Phase 14b) |

All in-Chat UX (cards for shift lists, availability, time-off confirmations, errors, quota-exhausted, onboarding) is **server-rendered** and lives in backend module M9 — the frontend team does not build those. Coordinate copy with the backend team there.

---

## 2. FE1 — Org admin: scheduling-agent toggle

**Where it lives.** The existing "Settings → Integrations → Google Chat" page (built for the notification module). Add a new section *below* the existing notification configuration.

**Section structure (proposed):**

```
┌─ Google Chat Integration ──────────────────────────────────────────┐
│                                                                    │
│  [existing notification config — connection status, cadence, etc.] │
│                                                                    │
│  ──────────────────────────────────────────────────────────────    │
│                                                                    │
│  ▸ Scheduling Assistant (AI)                            [ Off |On] │
│                                                                    │
│    Lets your employees ask the bot about their shifts,             │
│    availability, and time off — and update their own availability  │
│    — directly in Google Chat.                                      │
│                                                                    │
│    Each employee gets 50 free messages.                            │
│    [View usage & quota →]                                          │
│                                                                    │
│    Powered by Anthropic Claude. [Learn more about data handling →] │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

**Behavior.**
- Toggle reflects `organization_integrations.scheduling_agent_enabled` (column added in backend M13).
- Off → on: optimistic update; on confirmation, no other UI changes (employees with linked Chat accounts can immediately DM the bot).
- On → off: confirm dialog ("Employees will no longer be able to use the assistant. Existing message history is retained. Continue?"). Then PATCH and reflect.
- Disabled state when the parent notification integration isn't connected — the toggle is greyed out with a tooltip "Connect Google Chat first."

**API contract (defined in backend M13; also see future endpoints under M14):**

```
GET  /v1/api/organizations/:orgId/google-chat/agent
  → { enabled: boolean, freeMessagesPerUser: number, planTier: 'free' | 'paid' }

PATCH /v1/api/organizations/:orgId/google-chat/agent
  body: { enabled: boolean }
  → 200 { enabled: boolean }
```

**Copy.** Final wording lives in this doc — backend M9 cards (the in-Chat side) reference this copy where relevant. Keep it consistent.

---

## 3. FE2 — Org admin: usage & quota dashboard

**Why.** The org needs to see who's using the bot, who's hit the cap, and how much it's costing — before anyone gets surprised by a bill (or a frustrated employee).

**Where it lives.** New page under "Settings → Integrations → Google Chat → Scheduling Assistant → Usage" (linked from FE1's "View usage & quota" link).

**Sections:**

1. **Org-level summary card.**
   - Total messages this billing period.
   - Total estimated cost (USD).
   - Active employees (employees who sent ≥1 message).
   - Plan tier badge (Free / Paid).

2. **Per-employee table.**
   - Columns: Employee · Messages used · Quota remaining · Last activity · [Top up] action.
   - Sort by usage descending by default.
   - Filter: "Only show users near or at quota."
   - Pagination at 50/page.

3. **Trend chart (optional v1, defer if scope tight).**
   - Daily message count over last 30 days.
   - Daily cost overlay.

**API contract (defined in backend M14 / M16):**

```
GET /v1/api/organizations/:orgId/google-chat/agent/usage?from=...&to=...
  → {
      summary: {
        totalMessages: number;
        totalCostUsd: number;
        activeUsers: number;
        planTier: 'free' | 'paid';
      },
      perUser: Array<{
        userId: number;
        userName: string;
        messagesUsed: number;
        messagesGranted: number;
        remaining: number;
        lastActivityAt: string | null;
      }>,
      daily: Array<{ date: string; messages: number; costUsd: number }>
    }
```

**Empty / loading / error states.** Same pattern as the existing notification settings page. If the agent is disabled (FE1 toggle off), show an empty-state card with a "Turn on the assistant to see usage" link.

---

## 4. FE3 — Org admin: manual quota top-up (Phase 14a)

**Why.** Until paid-tier billing exists (Phase 14b), an org admin who wants an employee to keep using the bot past 50 messages needs a manual lever. This is intentionally simple — a single action, not a UX-rich purchase flow.

**Where it lives.** Inline action in the FE2 per-employee table: a "Top up" button per row.

**Behavior.**
- Click → modal: "Add more messages for {employee}. How many?" with presets (25 / 50 / 100) and a custom field. Reason field is optional but encouraged.
- Confirm → POST → optimistic update of the employee's `remaining` count.
- Audit: every top-up writes to a backend audit log (defined in M14). The reason field surfaces in the audit trail.

**API contract:**

```
POST /v1/api/organizations/:orgId/google-chat/agent/users/:userId/grant
  body: { additionalMessages: number, reason?: string }
  → 200 { messagesGranted: number, remaining: number }
```

**Permissions.** Org admin only — same RBAC layer the rest of the integrations page uses.

---

## 5. FE4 — Employee: notification preferences hint

**Why.** Employees who already use the notification bot won't necessarily know the agent capability is there. A small, unobtrusive hint on the existing notification preferences page is enough.

**Where it lives.** "My Profile → Notifications → Google Chat" — append a compact info card.

**Card content (proposed):**

```
💬 You can also DM the bot to ask about your schedule.
   Try: "what are my shifts this week?" or "I can't work next Tuesday."
   [Open Google Chat →]
```

**Behavior.**
- Show only when the org has FE1 enabled AND the employee has a linked Chat account.
- Hide when the employee is at quota (the bot already tells them in-Chat; don't double-up).
- "Open Google Chat" deep-links to `https://chat.google.com/` — no integration with the user's specific space; just nudges them to open Chat.

**API contract.** Existing notification preferences endpoint extended — backend M13 adds the `agentEnabledForOrg` field to the same payload the employee already fetches:

```
GET /v1/api/me/notifications
  → { …existing fields…, googleChat: { …existing…, agentEnabledForOrg: boolean } }
```

No new endpoints needed.

---

## 6. FE5 + FE6 — Future (Phase 14b billing surfaces)

These land when backend M14b ships. Frontend handoff for those will be added to this doc at that point. Today they are placeholders so we don't build FE2/FE3 in a way that conflicts with future billing flows.

**Anticipated shape:**
- FE5 — a "Plan" tab inside the Scheduling Assistant settings: current plan, message bundle size, overage rate, payment method, invoices. Integrates with whatever payment provider gets chosen.
- FE6 — when an employee hits quota, the in-Chat **quota-exhausted card** (M9) gets an "ask your admin to upgrade" action that emails / pings the admin (separate backend work).

**Frontend principle for today:** build FE2/FE3 such that adding a "Plan" tab later is purely additive — don't bake the manual top-up button into a component that assumes free-tier-only.

---

## 7. Design system & shared components

Reuse the existing notification module's frontend conventions:

- Same toggle component (FE1).
- Same table + pagination (FE2).
- Same modal pattern (FE3).
- Same info-card style (FE4).

If the HH design system has a "Settings → Integrations → [vendor]" template, this entire surface should be a single-page layout under it. Don't introduce a new top-level nav item.

Cross-reference: [HH-Frontend `employee-portal-ui` skill](../../integration-google-chat/frontend/integration-google-chat-frontend.md#design-system-pointers) — same pointers apply.

---

## 8. Testing checklist (frontend)

| Scenario | Manual / Automated | Notes |
|---|---|---|
| Toggle FE1 off → on; confirm bot accepts DMs immediately | Manual | Pair with a backend dev to watch the webhook log |
| Toggle FE1 on → off mid-thread; confirm bot replies with disabled card | Manual | Validates backend M13 integration test from the UI side |
| FE2 table renders with zero, one, and many users | Automated | Component test |
| FE2 table sort + filter behaves correctly with mixed quota states | Automated | Component test |
| FE3 top-up persists and reflects in FE2 row immediately | Manual + automated | E2E if available |
| FE3 modal validates: must be positive integer, max 1000 per top-up | Automated | Component test |
| FE4 hint hides for employees at quota | Manual | Toggle quota in DB to reproduce |
| Page loads and renders correctly when notification integration isn't connected (FE1 disabled, others gracefully empty) | Manual | Edge case |
| RTL layout (when multi-language lands — currently deferred) | Deferred | Tied to backend §6 Q3 |

---

## 9. Open questions (frontend)

1. **FE2 cost display granularity.** Show actual USD or "credits used"? Default proposal: USD for org admins, hidden from employee FE4. Confirm with product.
2. **FE3 default top-up amount.** 25 / 50 / 100? Default proposal: presets at 25, 50, 100, plus custom. Aligned with the 50-free baseline.
3. **FE4 placement.** Inline on the notifications page, or as a separate "Tips" expandable? Default proposal: inline, single info card.
4. **FE2 historical retention.** How far back can the dashboard show usage? Tied to backend M11 retention policy (default 90 days from §0/C6). Confirm.
