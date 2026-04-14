# Employee Availability — Frontend Integration Guide

## Overview

The availability system supports two types of rules:

| Type | Description | Key field |
|------|-------------|-----------|
| **Recurring** | Repeats weekly (e.g., every Monday 8am–4pm) | `day_of_week` (0=SUN … 6=SAT) |
| **Specific-date** | One-off availability for a particular date | `date` (YYYY-MM-DD) |

Both types are stored in the same `availability_rules` table and use the same REST endpoints.

---

## Base URL

```
/v1/api/employee/calendar/availability
```

All endpoints require a valid JWT in the `Authorization: Bearer <token>` header.

---

## Endpoints

### 1. Get availability rules

```
GET /v1/api/employee/calendar/availability
```

**Query parameters:**

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `organization_id` | UUID | No | Scope to a specific organization |
| `date` | YYYY-MM-DD | No | Return only rules for this specific date |

**Examples:**

```ts
// Get all recurring rules for an organization
GET /availability?organization_id=f729c499-...

// Get rules for a specific date (calendar day click)
GET /availability?date=2026-04-15&organization_id=f729c499-...
```

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "id": "a1b2c3d4-...",
      "user_id": "5263c1fe-...",
      "organization_id": "f729c499-...",
      "date": "2026-04-15",
      "day_of_week": 2,
      "start_time": "08:00:00",
      "end_time": "16:00:00",
      "is_available": true,
      "shift_type": null,
      "effective_from": null,
      "effective_until": null,
      "created_at": "2026-04-10T22:00:00.000Z",
      "updated_at": "2026-04-10T22:00:00.000Z"
    }
  ]
}
```

---

### 2. Bulk upsert availability rules

```
PUT /v1/api/employee/calendar/availability
```

Replaces all rules of the same type (date-specific or recurring) for the user + organization scope. Date-specific and recurring rules are independent — upserting one type does not delete the other.

**Request body:**

```json
{
  "organization_id": "f729c499-...",
  "rules": [...]
}
```

**Rule object fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `date` | `YYYY-MM-DD` | No | Set for specific-date rules. Omit for recurring. |
| `day_of_week` | `0–6` | Conditional | Required if `date` is not provided (0=SUN … 6=SAT). Auto-derived when `date` is set. |
| `start_time` | `HH:MM` | Yes | Start time (24-hour format) |
| `end_time` | `HH:MM` | Yes | End time (24-hour format) |
| `is_available` | `boolean` | No | Defaults to `true`. Set `false` to mark as unavailable. |
| `shift_type` | `string` | No | `"morning"`, `"afternoon"`, or `"night"` |
| `effective_from` | `ISO date` | No | When the recurring rule starts applying |
| `effective_until` | `ISO date` | No | When the recurring rule stops applying |

---

### 3. Create a single rule

```
POST /v1/api/employee/calendar/availability
```

Same rule object fields as above, plus an optional `organization_id`.

---

### 4. Delete a single rule

```
DELETE /v1/api/employee/calendar/availability/:id
```

---

## Frontend Usage Examples

### Setting availability for a specific calendar date

When the user clicks on April 15 and adds two time slots:

```ts
await api.put('/v1/api/employee/calendar/availability', {
  organization_id: orgId,
  rules: [
    { date: '2026-04-15', start_time: '08:00', end_time: '12:00', is_available: true },
    { date: '2026-04-15', start_time: '14:00', end_time: '18:00', is_available: true },
  ],
});
```

This replaces all existing date-specific rules for this user + org. Recurring rules are untouched.

### Setting recurring weekly availability

When the user configures their default weekly schedule:

```ts
await api.put('/v1/api/employee/calendar/availability', {
  organization_id: orgId,
  rules: [
    { day_of_week: 1, start_time: '08:00', end_time: '16:00' }, // Monday
    { day_of_week: 2, start_time: '08:00', end_time: '16:00' }, // Tuesday
    { day_of_week: 3, start_time: '08:00', end_time: '16:00' }, // Wednesday
    { day_of_week: 4, start_time: '10:00', end_time: '18:00' }, // Thursday
    { day_of_week: 5, start_time: '08:00', end_time: '14:00' }, // Friday
  ],
});
```

This replaces all existing recurring rules. Date-specific rules are untouched.

### Loading the calendar month view

To render availability indicators on the calendar, fetch recurring rules once and date-specific rules for the visible range:

```ts
// 1. Get recurring rules (fetch once, apply client-side to each day)
const { data: recurringRules } = await api.get('/v1/api/employee/calendar/availability', {
  params: { organization_id: orgId },
});

// Filter to recurring only (date === null)
const recurring = recurringRules.filter(r => r.date === null);

// 2. For a specific date the user clicks, fetch date-specific rules
const { data: dateRules } = await api.get('/v1/api/employee/calendar/availability', {
  params: { organization_id: orgId, date: '2026-04-15' },
});
```

### Rendering logic for a calendar day

```ts
function getAvailabilityForDate(
  date: string,  // 'YYYY-MM-DD'
  recurringRules: AvailabilityRule[],
  dateSpecificRules: AvailabilityRule[],
) {
  // Date-specific rules take precedence over recurring
  const specific = dateSpecificRules.filter(r => r.date === date);
  if (specific.length > 0) return specific;

  // Fall back to recurring rules matching this day-of-week
  const dayOfWeek = new Date(`${date}T00:00:00Z`).getUTCDay();
  return recurringRules.filter(r => r.day_of_week === dayOfWeek);
}
```

### Marking a date as unavailable

```ts
await api.put('/v1/api/employee/calendar/availability', {
  organization_id: orgId,
  rules: [
    { date: '2026-04-20', start_time: '00:00', end_time: '23:59', is_available: false },
  ],
});
```

---

## TypeScript Interfaces

```ts
interface AvailabilityRule {
  id: string;
  user_id: string;
  organization_id: string | null;
  date: string | null;          // 'YYYY-MM-DD' for specific-date, null for recurring
  day_of_week: number | null;   // 0=SUN..6=SAT, auto-derived when date is set
  start_time: string;           // 'HH:MM:SS'
  end_time: string;             // 'HH:MM:SS'
  is_available: boolean;
  shift_type: string | null;    // 'morning' | 'afternoon' | 'night'
  effective_from: string | null;
  effective_until: string | null;
  created_at: string;
  updated_at: string;
}

interface CreateAvailabilityRuleInput {
  date?: string;              // 'YYYY-MM-DD' — omit for recurring
  day_of_week?: number;       // required if date is not set
  start_time: string;         // 'HH:MM'
  end_time: string;           // 'HH:MM'
  is_available?: boolean;     // default: true
  shift_type?: 'morning' | 'afternoon' | 'night';
  effective_from?: string;
  effective_until?: string;
}

interface BulkUpsertAvailabilityInput {
  organization_id?: string;
  rules: CreateAvailabilityRuleInput[];
}
```

---

## Key Behaviors

1. **Bulk upsert scoping** — `PUT /availability` replaces rules by type. Sending date-specific rules only deletes existing date-specific rules. Recurring rules are independent and vice versa.

2. **`day_of_week` auto-derivation** — When `date` is provided, the backend auto-computes `day_of_week` from it. You never need to send both.

3. **Precedence** — Date-specific rules should take precedence over recurring rules in the UI. If a user has set specific availability for April 15, show that instead of the recurring Tuesday rule.

4. **AI assistant integration** — The scheduling AI assistant automatically picks up both recurring and date-specific availability when checking if an employee can cover a shift. No additional frontend work needed.
