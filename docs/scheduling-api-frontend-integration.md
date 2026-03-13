# Scheduling API – Frontend Integration Guide

How to hook the frontend up to the scheduling API (departments, stations, rooms, beds, shifts, and who’s assigned to which shift). Everything is scoped to one organization, so you’ll need the org ID and a valid JWT for someone who has OWNER, HR, or MANAGER in that org.

---

## How to call the API

**Base path:**  
`https://your-api-host/v1/api/organizations/:organizationId`

Use your real API host and replace `:organizationId` with the current organization’s UUID.

**Headers on every request:**

- `Authorization: Bearer <your_access_token>`
- `Content-Type: application/json` (for POST and PATCH)

If the user doesn’t have access to the org or the token is missing/invalid, you’ll get a 401 or 403. Handle those and show the right message (e.g. “Please sign in” or “You don’t have access to this organization”).

---

## What the API returns

**When something works (single item):**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "ICU",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "code": "ICU-01",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T10:00:00.000Z"
  },
  "timestamp": "2025-03-17T12:30:00.000Z"
}
```

The actual object in `data` depends on the endpoint (department, shift, etc.). You always get this wrapper: `success`, `statusCode`, `message`, `data`, `timestamp`.

**When you ask for a list (with pagination):**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "name": "ICU",
      "code": "ICU-01",
      "is_active": true,
      "sort_order": 1,
      "created_at": "2025-03-17T10:00:00.000Z",
      "updated_at": "2025-03-17T10:00:00.000Z"
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "name": "ER",
      "code": "ER-01",
      "is_active": true,
      "sort_order": 2,
      "created_at": "2025-03-17T10:05:00.000Z",
      "updated_at": "2025-03-17T10:05:00.000Z"
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T12:30:00.000Z"
}
```

So: `data` is the array of items, and `meta` tells you how many there are in total and what page you’re on. Use `meta.total` and `meta.totalPages` for your pagination UI.

**When something goes wrong (e.g. 400, 404, 403):**

```json
{
  "statusCode": 400,
  "message": "Employee not in this organization",
  "error": "Bad Request"
}
```

Use `statusCode` and `message` to show an error to the user. Don’t rely on a specific shape for error details beyond that unless we document it.

---

## How the data fits together

Think of it in two parts.

**1. Location hierarchy (org → department → station → room → bed)**  
You create these in order: first departments for the org, then stations inside a department, then rooms inside a station, then beds inside a room. Every ID you get back (e.g. `department_id`, `station_id`) you’ll use in the next create or in the path for the next level.

**2. Shifts and who works them**  
A “shift” is just a time window (and maybe recurrence). It doesn’t say who is working. To say “this employee works this shift at this location,” you create an “employee shift” (assignment) that links: shift + employee + optionally department/station/room/bed.

So: build the hierarchy first, then create shifts, then create employee-shifts to assign people (and optionally a location) to each shift.

---

## Departments

All department URLs look like:  
`/v1/api/organizations/:organizationId/departments`  
and for one department:  
`/v1/api/organizations/:organizationId/departments/:departmentId`

### GET – List departments

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments`
- Query params (all optional):  
  - `is_active` – `true` or `false` to filter  
  - `page` – default 1  
  - `limit` – default 20, max 100  

Example URL:  
`/v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/departments?page=1&limit=20`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "name": "ICU",
      "code": "ICU-01",
      "is_active": true,
      "sort_order": 1,
      "created_at": "2025-03-17T10:00:00.000Z",
      "updated_at": "2025-03-17T10:00:00.000Z"
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "name": "ER",
      "code": "ER-01",
      "is_active": true,
      "sort_order": 2,
      "created_at": "2025-03-17T10:05:00.000Z",
      "updated_at": "2025-03-17T10:05:00.000Z"
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T12:30:00.000Z"
}
```

### GET – Get one department

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId`

Example:  
`/v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/departments/a1b2c3d4-e5f6-7890-abcd-ef1234567890`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "name": "ICU",
    "code": "ICU-01",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T10:00:00.000Z"
  },
  "timestamp": "2025-03-17T12:30:00.000Z"
}
```

### POST – Create department

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments`
- Body: JSON. Only `name` is required. Rest is optional.

**Request body (full example):**

```json
{
  "name": "ICU",
  "code": "ICU-01",
  "is_active": true,
  "sort_order": 1
}
```

Minimal body: `{ "name": "ICU" }` – then `code` will be null, `is_active` true, `sort_order` null.

**Response (201)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "name": "ICU",
    "code": "ICU-01",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T10:00:00.000Z"
  },
  "timestamp": "2025-03-17T12:30:00.000Z"
}
```

Store `data.id` – that’s the `departmentId` you’ll use for stations and in paths.

### PATCH – Update department

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId`
- Body: any subset of the create fields. Only send what you want to change.

**Request body (example – change name and deactivate):**

```json
{
  "name": "ICU (Intensive Care)",
  "is_active": false
}
```

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "name": "ICU (Intensive Care)",
    "code": "ICU-01",
    "is_active": false,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T12:35:00.000Z"
  },
  "timestamp": "2025-03-17T12:35:00.000Z"
}
```

### DELETE – Delete department

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId`
- No body.

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Department deleted",
  "data": null,
  "timestamp": "2025-03-17T12:40:00.000Z"
}
```

Deleting a department will cascade and remove its stations, rooms, and beds (and any employee-shift links to those). So only call this when you really mean to remove the whole branch.

---

## Stations

Stations live under a department. Every URL needs both `organizationId` and `departmentId` in the path.

Base path:  
`/v1/api/organizations/:organizationId/departments/:departmentId/stations`

### GET – List stations

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations`
- Query (optional): `is_active`, `page`, `limit`

Example:  
`/v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/departments/a1b2c3d4-e5f6-7890-abcd-ef1234567890/stations?page=1&limit=20`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "North Station",
      "code": "NS-01",
      "is_active": true,
      "sort_order": 1,
      "created_at": "2025-03-17T10:10:00.000Z",
      "updated_at": "2025-03-17T10:10:00.000Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T12:45:00.000Z"
}
```

### GET – Get one station

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "North Station",
    "code": "NS-01",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:10:00.000Z",
    "updated_at": "2025-03-17T10:10:00.000Z"
  },
  "timestamp": "2025-03-17T12:45:00.000Z"
}
```

### POST – Create station

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations`
- Body: JSON. Only `name` required.

**Request body (full example):**

```json
{
  "name": "North Station",
  "code": "NS-01",
  "is_active": true,
  "sort_order": 1
}
```

**Response (201)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "North Station",
    "code": "NS-01",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:10:00.000Z",
    "updated_at": "2025-03-17T10:10:00.000Z"
  },
  "timestamp": "2025-03-17T12:45:00.000Z"
}
```

Use `data.id` as `stationId` for rooms.

### PATCH – Update station

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId`
- Body: same fields as create, all optional. Example: `{ "name": "North Nursing Station", "sort_order": 2 }`

**Response (200)**  
Same shape as “Get one station” – full station object in `data`.

### DELETE – Delete station

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId`
- No body.

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Station deleted",
  "data": null,
  "timestamp": "2025-03-17T12:50:00.000Z"
}
```

---

## Rooms

Rooms live under a station. Path includes org, department, and station IDs.

Base path:  
`/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms`

### GET – List rooms

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms`
- Query (optional): `is_active`, `page`, `limit`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "name": "101",
      "is_active": true,
      "sort_order": 1,
      "created_at": "2025-03-17T10:15:00.000Z",
      "updated_at": "2025-03-17T10:15:00.000Z"
    },
    {
      "id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "name": "102",
      "is_active": true,
      "sort_order": 2,
      "created_at": "2025-03-17T10:16:00.000Z",
      "updated_at": "2025-03-17T10:16:00.000Z"
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T12:55:00.000Z"
}
```

### GET – Get one room

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "name": "101",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:15:00.000Z",
    "updated_at": "2025-03-17T10:15:00.000Z"
  },
  "timestamp": "2025-03-17T12:55:00.000Z"
}
```

### POST – Create room

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms`
- Body: JSON. Only `name` required.

**Request body (full example):**

```json
{
  "name": "101",
  "is_active": true,
  "sort_order": 1
}
```

**Response (201)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "name": "101",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:15:00.000Z",
    "updated_at": "2025-03-17T10:15:00.000Z"
  },
  "timestamp": "2025-03-17T12:55:00.000Z"
}
```

Use `data.id` as `roomId` for beds.

### PATCH – Update room

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId`
- Body: e.g. `{ "name": "101-A", "is_active": false }` (all optional).

**Response (200)**  
Full room object in `data`, same shape as “Get one room”.

### DELETE – Delete room

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId`
- No body.

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Room deleted",
  "data": null,
  "timestamp": "2025-03-17T13:00:00.000Z"
}
```

---

## Beds

Beds live under a room. Path includes org, department, station, and room IDs.

Base path:  
`/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds`

### GET – List beds

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds`
- Query (optional): `is_active`, `page`, `limit`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
      "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "bed_number": "A",
      "is_active": true,
      "created_at": "2025-03-17T10:20:00.000Z",
      "updated_at": "2025-03-17T10:20:00.000Z"
    },
    {
      "id": "a7b8c9d0-e1f2-3456-0123-567890123456",
      "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "bed_number": "B",
      "is_active": true,
      "created_at": "2025-03-17T10:21:00.000Z",
      "updated_at": "2025-03-17T10:21:00.000Z"
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T13:05:00.000Z"
}
```

### GET – Get one bed

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds/:bedId`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_number": "A",
    "is_active": true,
    "created_at": "2025-03-17T10:20:00.000Z",
    "updated_at": "2025-03-17T10:20:00.000Z"
  },
  "timestamp": "2025-03-17T13:05:00.000Z"
}
```

### POST – Create bed

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds`
- Body: JSON. Only `bed_number` required.

**Request body (full example):**

```json
{
  "bed_number": "A",
  "is_active": true
}
```

**Response (201)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_number": "A",
    "is_active": true,
    "created_at": "2025-03-17T10:20:00.000Z",
    "updated_at": "2025-03-17T10:20:00.000Z"
  },
  "timestamp": "2025-03-17T13:05:00.000Z"
}
```

### PATCH – Update bed

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds/:bedId`
- Body: e.g. `{ "bed_number": "A1", "is_active": false }` (all optional).

**Response (200)**  
Full bed object in `data`, same shape as “Get one bed”.

### DELETE – Delete bed

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds/:bedId`
- No body.

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Bed deleted",
  "data": null,
  "timestamp": "2025-03-17T13:10:00.000Z"
}
```

---

## Shifts

Shifts are org-level. They only define when the shift is (and optionally how it repeats). Who works that shift (and where) is stored in employee-shifts.

Base path:  
`/v1/api/organizations/:organizationId/shifts`

### GET – List shifts

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/shifts`
- Query (all optional):  
  - `from_date` – ISO date (YYYY-MM-DD), only shifts that start on or after this date  
  - `to_date` – ISO date, only shifts that end on or before this date  
  - `shift_type` – e.g. "DAY", "NIGHT"  
  - `status` – e.g. "ACTIVE"  
  - `recurrence_type` – ONE_TIME, FULL_WEEK, WEEKDAYS, WEEKENDS, CUSTOM  
  - `page`, `limit`

Example:  
`/v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/shifts?from_date=2025-03-17&to_date=2025-03-31&page=1&limit=20`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "start_at": "2025-03-17T07:00:00.000Z",
      "end_at": "2025-03-17T15:00:00.000Z",
      "shift_type": "DAY",
      "name": "Morning shift",
      "status": "ACTIVE",
      "recurrence_type": "FULL_WEEK",
      "recurrence_days": null,
      "recurrence_start_date": "2025-03-17",
      "recurrence_end_date": "2025-03-31",
      "created_at": "2025-03-17T11:00:00.000Z",
      "updated_at": "2025-03-17T11:00:00.000Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T13:15:00.000Z"
}
```

`recurrence_days` is a string when set, e.g. `"1,2,3,4,5"` for Mon–Fri (1 = Monday, 7 = Sunday). For ONE_TIME it’s null.

### GET – Get one shift

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "start_at": "2025-03-17T07:00:00.000Z",
    "end_at": "2025-03-17T15:00:00.000Z",
    "shift_type": "DAY",
    "name": "Morning shift",
    "status": "ACTIVE",
    "recurrence_type": "FULL_WEEK",
    "recurrence_days": null,
    "recurrence_start_date": "2025-03-17",
    "recurrence_end_date": "2025-03-31",
    "created_at": "2025-03-17T11:00:00.000Z",
    "updated_at": "2025-03-17T11:00:00.000Z"
  },
  "timestamp": "2025-03-17T13:15:00.000Z"
}
```

The backend may optionally include an `employeeShifts` array on this object when it’s useful; if present, use it to show who’s on the shift without a second request.

### POST – Create shift

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/shifts`
- Body: JSON. Required: `start_at`, `end_at`. Everything else optional.

**Request body – one-time shift:**

```json
{
  "start_at": "2025-03-17T07:00:00.000Z",
  "end_at": "2025-03-17T15:00:00.000Z",
  "shift_type": "DAY",
  "name": "Morning shift"
}
```

**Request body – recurring (e.g. full week for a date range):**

```json
{
  "start_at": "2025-03-17T07:00:00.000Z",
  "end_at": "2025-03-17T15:00:00.000Z",
  "shift_type": "DAY",
  "name": "Morning shift",
  "recurrence_type": "FULL_WEEK",
  "recurrence_start_date": "2025-03-17",
  "recurrence_end_date": "2025-03-31"
}
```

**Request body – custom days (e.g. Mon, Wed, Fri only):**

```json
{
  "start_at": "2025-03-17T07:00:00.000Z",
  "end_at": "2025-03-17T15:00:00.000Z",
  "shift_type": "DAY",
  "name": "Morning shift",
  "recurrence_type": "CUSTOM",
  "recurrence_start_date": "2025-03-17",
  "recurrence_end_date": "2025-03-31",
  "recurrence_days": [1, 3, 5]
}
```

Allowed `recurrence_type`: `ONE_TIME`, `FULL_WEEK`, `WEEKDAYS`, `WEEKENDS`, `CUSTOM`. For `CUSTOM`, `recurrence_days` is an array of numbers 1–7 (1 = Monday, 7 = Sunday).

**Response (201)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "start_at": "2025-03-17T07:00:00.000Z",
    "end_at": "2025-03-17T15:00:00.000Z",
    "shift_type": "DAY",
    "name": "Morning shift",
    "status": "ACTIVE",
    "recurrence_type": "FULL_WEEK",
    "recurrence_days": null,
    "recurrence_start_date": "2025-03-17",
    "recurrence_end_date": "2025-03-31",
    "created_at": "2025-03-17T11:00:00.000Z",
    "updated_at": "2025-03-17T11:00:00.000Z"
  },
  "timestamp": "2025-03-17T13:15:00.000Z"
}
```

Use `data.id` when assigning employees to this shift (employee-shifts).

### PATCH – Update shift

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId`
- Body: any of the create fields + `status`. All optional. Example: `{ "name": "Morning shift (updated)", "status": "ACTIVE" }`

**Response (200)**  
Full shift object in `data`, same shape as “Get one shift”.

### DELETE – Delete shift

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId`
- No body.

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Shift deleted",
  "data": null,
  "timestamp": "2025-03-17T13:20:00.000Z"
}
```

Deleting a shift also deletes all employee-shifts for that shift.

---

## Employee-shifts (assigning someone to a shift)

An “employee shift” is the link between one shift and one employee, plus optional location (department/station/room/bed) and notes/status. One employee can only be assigned once per shift; if you try to assign the same person again you get 409 Conflict.

### GET – List assignments for a shift

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId/employee-shifts`
- Query (optional): `employee_id` (uuid), `status`, `page`, `limit`

Example:  
`/v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/shifts/b8c9d0e1-f2a3-4567-1234-678901234567/employee-shifts?page=1&limit=20`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "c9d0e1f2-a3b4-5678-2345-789012345678",
      "shift_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
      "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789",
      "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "room_id": null,
      "bed_id": null,
      "status": "SCHEDULED",
      "notes": "Covering for nurse A",
      "actual_start_at": null,
      "actual_end_at": null,
      "created_at": "2025-03-17T11:30:00.000Z",
      "updated_at": "2025-03-17T11:30:00.000Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T13:25:00.000Z"
}
```

The backend may nest `employee`, `department`, `station`, etc. in each item when it loads relations; if you see those, you can use them for labels without extra lookups.

### POST – Assign employee to shift

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId/employee-shifts`
- Body: JSON. Required: `employee_id`. Optional: `department_id`, `station_id`, `room_id`, `bed_id`, `status`, `notes`. Sending at least one location (department/station/room/bed) is a good idea so you know where they’re working.

**Request body (full example):**

```json
{
  "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789",
  "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "room_id": null,
  "bed_id": null,
  "status": "SCHEDULED",
  "notes": "Covering for nurse A"
}
```

Minimal: `{ "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789" }`. The employee must belong to the same organization or you’ll get 400.

**Response (201)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c9d0e1f2-a3b4-5678-2345-789012345678",
    "shift_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "room_id": null,
    "bed_id": null,
    "status": "SCHEDULED",
    "notes": "Covering for nurse A",
    "actual_start_at": null,
    "actual_end_at": null,
    "created_at": "2025-03-17T11:30:00.000Z",
    "updated_at": "2025-03-17T11:30:00.000Z"
  },
  "timestamp": "2025-03-17T13:25:00.000Z"
}
```

Store `data.id` – that’s the employee-shift ID you use for “get one”, “update”, and “remove assignment”.

### GET – Get one assignment

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c9d0e1f2-a3b4-5678-2345-789012345678",
    "shift_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "room_id": null,
    "bed_id": null,
    "status": "SCHEDULED",
    "notes": "Covering for nurse A",
    "actual_start_at": null,
    "actual_end_at": null,
    "created_at": "2025-03-17T11:30:00.000Z",
    "updated_at": "2025-03-17T11:30:00.000Z"
  },
  "timestamp": "2025-03-17T13:30:00.000Z"
}
```

When the backend loads relations, `data` might also contain nested objects like `shift`, `employee`, `department`, `station`, `room`, `bed` – use those for display (e.g. employee name, department name).

### PATCH – Update assignment (e.g. move location, clock-in/out, complete)

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`
- Body: any subset of the following; all optional.  
  - `department_id`, `station_id`, `room_id`, `bed_id` (use null to clear)  
  - `status`  
  - `notes`  
  - `actual_start_at`, `actual_end_at` – ISO datetime strings for clock-in and clock-out  

**Request body – mark completed with times:**

```json
{
  "status": "COMPLETED",
  "actual_start_at": "2025-03-17T07:05:00.000Z",
  "actual_end_at": "2025-03-17T14:55:00.000Z"
}
```

**Request body – change location only:**

```json
{
  "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
  "bed_id": "f6a7b8c9-d0e1-2345-f012-456789012345"
}
```

**Response (200)**  
Full employee-shift object in `data`, same shape as “Get one assignment” (with any nested relations the backend includes).

### DELETE – Remove assignment

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`
- No body.

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Employee shift removed",
  "data": null,
  "timestamp": "2025-03-17T13:35:00.000Z"
}
```

---

## Employee’s shifts (list by employee)

Convenience endpoint: “give me all assignments for this employee,” e.g. for an employee’s schedule view.

### GET – List shifts for an employee

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/employees/:employeeId/shifts`
- Query (optional): `from_date`, `to_date` (ISO dates), `status`, `page`, `limit`

Example:  
`/v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/employees/d0e1f2a3-b4c5-6789-3456-890123456789/shifts?from_date=2025-03-01&to_date=2025-03-31&page=1&limit=20`

**Response (200)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "c9d0e1f2-a3b4-5678-2345-789012345678",
      "shift_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
      "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789",
      "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "room_id": null,
      "bed_id": null,
      "status": "SCHEDULED",
      "notes": "Covering for nurse A",
      "actual_start_at": null,
      "actual_end_at": null,
      "created_at": "2025-03-17T11:30:00.000Z",
      "updated_at": "2025-03-17T11:30:00.000Z"
    }
  ],
  "meta": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T13:40:00.000Z"
}
```

Each item is an employee-shift. The backend may attach the related `shift` (and maybe location) so you can show time and place without extra requests. If you only get IDs, use the shift and department/station/room/bed list endpoints to resolve names.

---

## Where to get IDs

- **organizationId** – From your app state (e.g. after login or org switcher). Same org ID for the whole scheduling section.
- **employee_id** – From your existing employees/list API for that org. Must be an employee of this organization.
- **department_id, station_id, room_id, bed_id** – From the scheduling endpoints above. Create department → get id → create stations under it → get station id → and so on. Only use IDs that belong to this org; the API will reject others.

---

## Quick checklist for the frontend

1. Send `Authorization: Bearer <token>` and `Content-Type: application/json` on every request.
2. Build hierarchy in order: departments → stations → rooms → beds. Use the IDs from each create in the next path or body.
3. For shifts, use `start_at` and `end_at` as ISO strings; for recurrence use `recurrence_type` and, for CUSTOM, `recurrence_days` as [1–7].
4. When assigning someone to a shift, POST to `.../shifts/:shiftId/employee-shifts` with `employee_id` and optionally location IDs. Same employee twice on the same shift returns 409.
5. To show one employee’s schedule, GET `.../employees/:employeeId/shifts` with `from_date` and `to_date`.
6. To record clock-in/out or mark done, PATCH the employee-shift with `actual_start_at`, `actual_end_at`, and/or `status: "COMPLETED"`.
7. Handle 4xx/5xx by reading `statusCode` and `message` and showing a clear message to the user.

If something in this doc doesn’t match what the API returns, tell the backend dev and we can fix either the API or the doc.
