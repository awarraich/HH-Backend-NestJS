---
name: google-chat-integration-docs
description: Use this skill whenever you make any change related to the Google Chat integration — backend code (controllers, services, entities, migrations under src/models/notifications or anything touching user_chat_connections / organization_integrations / notification_dispatch_log / the Chat webhook / document-expiry dispatcher), Google Cloud Console / Marketplace setup, frontend org-admin or employee UI for Chat, dev environment setup (ngrok, GOOGLE_CHAT_* env vars), or architectural decisions. As part of the same task, update the docs under docs/integration-google-chat/ so they stay in sync with reality.
---

# Google Chat integration: keep the docs in sync

The integration docs live under `docs/integration-google-chat/` and are split by where the work happens:

- **`docs/integration-google-chat/backend/`** — backend implementation docs:
  - **[integration-google-chat.md](../../../docs/integration-google-chat/backend/integration-google-chat.md)** — design doc. Architecture, decisions, schemas, ASCII mockups, MVP cut, open design questions. Changes infrequently after decisions are made.
  - **[integration-google-chat-plan.md](../../../docs/integration-google-chat/backend/integration-google-chat-plan.md)** — execution plan. Module-by-module status (✅ / 🚧 / ❌ / 💤), what's done per module, what's remaining, future enhancements (F1, F2, …). Changes constantly as work progresses.
- **`docs/integration-google-chat/frontend/`** — frontend handoff:
  - **[integration-google-chat-frontend.md](../../../docs/integration-google-chat/frontend/integration-google-chat-frontend.md)** — self-contained frontend implementation guide. API contracts (org admin live, employee planned), four employee states, three-step org-admin wizard, copy/wording, design-system pointers, suggested file layout, testing checklist. Cross-references HH-Frontend's `employee-portal-ui` skill.

Every Google Chat integration task ends with the relevant docs reflecting the new state.

## What counts as "Google Chat integration work"

Trigger this skill when the change involves any of:

- **Backend**: files under `src/models/notifications/`, the Chat webhook endpoint, signature verification, the bot event handlers, the dispatcher / cron / channel adapters, or any migration/entity for `user_chat_connections`, `organization_integrations`, `notification_dispatch_log`, `notification_preferences`.
- **Google Cloud Console**: Chat app config, OAuth consent screen, service account, Marketplace listing.
- **Frontend**: pages/components for "Settings → Integrations → Google Chat" (org admin) or "My Profile → Notifications" (employee, Chat states 1–4).
- **Dev environment**: ngrok config, webhook URL changes, new env vars prefixed `GOOGLE_CHAT_`.
- **Decisions**: architecture choices, scope changes, resolutions of open questions.

When in doubt, update the docs.

## Which file gets which kind of update

The two backend files have different purposes; route updates accordingly.

### Goes in the design doc (`backend/integration-google-chat.md`)

| Change type | Section |
|---|---|
| New architectural decision | "Architectural decisions" — append a numbered item, don't renumber |
| Schema change (column added, type changed) | The relevant migration block under "Phase 1 — Data model & config plumbing" |
| New event type, security mechanism, or handler shape | "Phase 2 — Bot event endpoint" |
| Cadence, dispatcher, or channel-routing rules | "Phase 3 — Dispatcher, scanner & cron" |
| New org-admin or employee screen / UX flow | Phase 4 / Phase 5 ASCII mockup |
| Marketplace requirement learned from Google | "Phase 6 — Marketplace publication" |
| ngrok / local-dev workflow tweak | "Local dev setup" |
| Resolved open question | Remove from "Open design questions"; reflect decision in the relevant phase |
| Item from MVP cut moves into v1 | Strike it from "MVP cut," update the phase |

### Goes in the plan doc (`backend/integration-google-chat-plan.md`)

| Change type | Section |
|---|---|
| Module status flips (❌ → 🚧 → ✅) | Module's status marker AND the "Quick status" table at top |
| File created/modified for an integration module | That module's "Done" subsection — link the file with a relative path (note: paths from `docs/integration-google-chat/backend/` to `src/` need `../../../src/...`) |
| Module's remaining work changes | Module's "Remaining" subsection — edit in place |
| New future enhancement identified | "Future enhancements" section — add as next F-number (F1, F2, …) |
| Future enhancement gets implemented | Move it into the relevant module's "Done" section; strike it from "Future enhancements"; do NOT renumber surviving F-items |
| Module gets blocked / unblocked | Module status (🚧) + a one-line note in "Remaining" |
| Working-agreement change | "Working agreements" section |

### Goes in both

| Change type | Where |
|---|---|
| New phase / module added | New phase section in design doc + new module row in plan's quick-status table + new module section in plan |
| Decision that changes a module's scope | Decision in design doc + remaining-work edit in plan |

## Frontend docs

`docs/integration-google-chat/frontend/integration-google-chat-frontend.md` is the canonical frontend handoff. **Backend changes that affect the frontend contract — new endpoints, response-shape changes, new behavior the UI needs to surface — must update the frontend doc's API contracts section in the same task.** The backend design doc keeps high-level UI mockups (Phases 4 + 5) but the frontend doc is the source of truth for endpoint shapes, state machines, copy, and design-system usage.

When the frontend developer starts implementing screens, frontend-specific changes (component decisions, state-management choices, UX polish) get logged in the frontend doc — not the backend design doc. If frontend work grows enough to warrant its own execution tracker, create a sibling `integration-google-chat-frontend-plan.md` and split design-vs-execution the same way the backend folder does.

When updating the frontend doc:

- API contract changes: update both the contract section AND the relevant "Done"/"Remaining" subsection in the backend plan (since the contract changes are usually backend-driven).
- Copy changes: keep the canonical copy table in the frontend doc; the backend doc's mockups can stay slightly aspirational.
- New employee states or admin wizard steps: update the frontend doc's screen sections AND the backend design doc's Phase 4/5 mockups.
- HH-Frontend implementation details (file paths, hook names, component breakdown): frontend doc only.

## How to update

- **Concrete and short.** One paragraph max per change. Reference files via relative links from the doc's location: from `docs/integration-google-chat/backend/`, source files are at `../../../src/...`.
- **Edit in place; don't append history.** When a phase or module transitions from "planned" → "done," update the wording. Don't pile up "Update: …" paragraphs or "Completed on YYYY-MM-DD" rows.
- **Status markers.** Plan doc uses ✅ / 🚧 / ❌ / 💤. Design doc uses ✅ / 🚧 prefixed on phase headings. Update both the marker AND the "Quick status" table when a module's state changes.
- **Preserve mockups, schemas, and tables.** If schema or UI flow changes, edit the existing column tables / ASCII mockups in place — don't add a second copy.
- **Keep F-numbers stable.** Future-enhancement IDs (F1, F2, …) are referenced from elsewhere; never renumber them when items get implemented or removed.
- **Every module needs a Verified subsection.** A module is not ✅ until exercised end-to-end. When flipping status to ✅, add a **Verified:** subsection alongside **Done:** in the plan that names the test (curl, real Chat event, DB query, UI flow, etc.) and the observed result. Untested code stays 🚧.

## When NOT to update the docs

Skip the update if the change is purely cosmetic (formatting, lint, comment-only) or unrelated to the integration even if a nearby file. The docs track design and progress, not every commit.

## Commit when a module is completed

Once a module flips to ✅ in the plan **and** the docs reflect the new state, create a git commit for that module. This is a standing instruction from the user — you don't need to ask before committing on integration modules; the rule is the authorization.

**What to stage** — only files relevant to that module's work, plus the doc updates from the same task. Use specific paths, never `git add -A` or `git add .`. Typical surface for one module:

- New/modified files under `src/models/notifications/`, `src/jobs/{producers,consumers}/reminder-dispatch/`, `src/config/google-chat/`, `src/database/migrations/<timestamp>-...`.
- Module-related migration registry edits in `src/database/migrations/index.ts`.
- Module-related entry edits in `src/app.module.ts` (the AppModule import + imports array).
- Updated `package.json` + `package-lock.json` if the module added a dependency (BullMQ, googleapis, etc.).
- Updated `docs/integration-google-chat/backend/integration-google-chat-plan.md`, `backend/integration-google-chat.md`, and/or `frontend/integration-google-chat-frontend.md`.
- Updated `.gitignore` if the module added an ignore pattern (e.g. `secrets/`).

**Never stage:**

- `.env` (contains real credentials).
- Anything under `secrets/` (service account JSON, private keys).
- Other modules' WIP that happens to be in the working tree.

**Commit message format:**

```
google-chat integration: module N — <short summary>

<one short paragraph: what shipped + how it was verified>

Co-Authored-By: Claude <noreply@anthropic.com>
```

Use a HEREDOC for the body so newlines render correctly. Examples of the short summary:

- `module 4 — JWT signature verification on the bot webhook`
- `module 8 — GoogleChatChannelService.sendDirectMessage`
- `module 12 — BullMQ producer + consumer with rate limit`
- `module 13 — org admin REST endpoints under /v1/api/organizations/.../google-chat`

**Order of operations** for each completed module:

1. Code is written and verified end-to-end.
2. Both relevant docs (backend plan, design doc, and/or frontend doc) are updated to reflect ✅.
3. Run `git status` to see what's about to be staged.
4. Run `git add` with explicit file paths for the module — never `-A`.
5. Run `git status` again to confirm only the intended files are staged.
6. Commit with the format above.
7. Run `git status` after the commit to confirm a clean module surface (other modules' WIP may remain in the tree — that's expected).

**Do not push** unless the user explicitly asks. Commits stay local until they request a push or PR.

**Do not amend.** If a commit needs follow-up (a missed file, a typo in the message), create a new commit. Amending feels tidier but loses the original verification timestamp.

**Pre-commit hook failures:** if a hook fails, fix the underlying issue and re-stage + commit fresh — never use `--no-verify` to bypass.

## Test data and identifiers — stay inside this project

When verifying a module end-to-end (test emails, test DMs, test users, test orgs), use only identifiers that exist in this project's data or that the user has explicitly provided for this project. Do **not** pull emails, account names, or other identifiers from the system-context environment (e.g. the `userEmail` field), other repos, or unrelated tools — those may belong to different projects and can cause real side effects (test emails landing in the wrong inbox, test data scoped to the wrong tenant). When in doubt, ask the user which identifier to use rather than assuming.

## Implicit responsibility

A Google Chat integration task is not done until the relevant docs under `docs/integration-google-chat/` reflect the new state. Verify they were updated before reporting completion to the user.
