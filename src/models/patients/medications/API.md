# Patient Medications API

## Mark medication as taken

**Endpoint:** `POST /v1/api/patients/me/medications/:medicationId/taken`

**Request body:**
```json
{
  "timeSlot": "8:00 AM",
  "date": "2026-02-18"
}
```

| Field     | Type   | Required | Description                                      |
|-----------|--------|----------|--------------------------------------------------|
| timeSlot  | string | yes      | Must match one of the medication's time slots   |
| date      | string | yes      | ISO date (YYYY-MM-DD) for the scheduled dose    |

**Response (200):**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "timeSlot": "8:00 AM",
    "taken": true,
    "recordedAt": "2026-02-18T08:05:00.000Z"
  },
  "timestamp": "2026-02-18T12:00:00.000Z"
}
```

**Errors:** 400 if `timeSlot` is not configured for the medication or `date` is invalid; 404 if medication not found.

---

## Delete medication

**Endpoint:** `DELETE /v1/api/patients/me/medications/:medicationId`

**Request body:** None.

**Response (200):**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Medication removed",
  "data": {
    "id": "uuid-medication-id",
    "deleted": true
  },
  "timestamp": "2026-02-18T12:00:00.000Z"
}
```

**Note:** Delete is a soft delete (sets `deleted_at`). The medication no longer appears in list/get and cannot be updated or marked as taken.

**Errors:** 404 if medication not found or already deleted.
