# Scheduling API Reference

This document describes the REST API for managing an organization’s facility structure (departments, stations, rooms, beds, chairs) and shift scheduling (shifts and employee assignments). All endpoints are scoped to a single organization and require a user with OWNER, HR, or MANAGER role in that organization.

---

## Base URL and headers

**Base path**

```
/v1/api/organizations/:organizationId
```

Replace `:organizationId` with the current organization’s UUID. Prepend your API host (e.g. `https://api.example.com`).

**Required headers**

| Header             | Value                    |
|--------------------|--------------------------|
| `Authorization`    | `Bearer <access_token>`  |
| `Content-Type`     | `application/json`       |

Use for every request. Missing or invalid token returns 401; insufficient role returns 403.

---

## Response format

**Single resource (GET one, POST, PATCH)**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": { },
  "timestamp": "2025-03-17T12:00:00.000Z"
}
```

`data` holds the created, updated, or fetched resource. For POST create, `statusCode` in the envelope is typically 200; HTTP status is 201.

**Paginated list (GET list endpoints)**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [ ],
  "meta": {
    "total": 42,
    "page": 1,
    "limit": 20,
    "totalPages": 3
  },
  "timestamp": "2025-03-17T12:00:00.000Z"
}
```

`data` is the array of items. Use `meta.total`, `meta.page`, `meta.limit`, and `meta.totalPages` for pagination.

**Error (4xx / 5xx)**

```json
{
  "statusCode": 400,
  "message": "Employee not in this organization",
  "error": "Bad Request"
}
```

Use `statusCode` and `message` for user-facing error handling.

---

## Data model

**Location hierarchy**

- **Organization** → **Department** → **Station** → **Room** → **Bed** or **Chair**
- Departments have an optional type (e.g. nursing, clinic) and description.
- Stations have location, staffing requirements, multi-station coverage flags, and room configuration (beds vs chairs). Rooms can be created one-by-one or in bulk when creating a station.
- Rooms have optional location/wing, floor, and configuration (beds or chairs) with capacity counts.
- Beds and chairs are per-room; each bed or chair has an identifier (e.g. bed number, chair number). Employee assignments can reference a specific bed or chair.

**Scheduling**

- **Shift** – Organization-level time window (and optional recurrence). Defines when a shift occurs, not who works it.
- **Employee shift** – Assignment of one employee to one shift, with optional location (department, station, room, and either bed or chair) and status/notes.

Create the location hierarchy first, then shifts, then employee-shifts to assign people (and optionally a bed or chair) to shifts.

---

## Departments

Base path: `/v1/api/organizations/:organizationId/departments`

### GET – List departments

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments`
- Query (all optional): `is_active` (boolean), `page` (default 1), `limit` (default 20, max 100)

**Example URL**

```
GET /v1/api/organizations/f9e8d7c6-b5a4-3210-fedc-ba0987654321/departments?page=1&limit=20
```

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "name": "Nursing",
      "code": "NUR",
      "description": "Patient care and medical services",
      "department_type": "NURSING",
      "is_active": true,
      "sort_order": 1,
      "created_at": "2025-03-17T10:00:00.000Z",
      "updated_at": "2025-03-17T10:00:00.000Z",
      "stationCount": 3
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
      "name": "Kitchen",
      "code": "KIT",
      "description": "Food preparation and dietary services",
      "department_type": "OTHER",
      "is_active": true,
      "sort_order": 2,
      "created_at": "2025-03-17T10:05:00.000Z",
      "updated_at": "2025-03-17T10:05:00.000Z",
      "stationCount": 1
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T12:00:00.000Z"
}
```

`stationCount` is the number of stations in that department.

### GET – Get one department

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId`

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "name": "Nursing",
    "code": "NUR",
    "description": "Patient care and medical services",
    "department_type": "NURSING",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T10:00:00.000Z"
  },
  "timestamp": "2025-03-17T12:00:00.000Z"
}
```

### POST – Create department

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments`
- Body: JSON. Only `name` is required.

**Request body (all fields)**

```json
{
  "name": "Nursing",
  "code": "NUR",
  "description": "Patient care and medical services",
  "department_type": "NURSING",
  "is_active": true,
  "sort_order": 1
}
```

**Minimal request body**

```json
{
  "name": "Nursing"
}
```

**Response 201**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "name": "Nursing",
    "code": "NUR",
    "description": "Patient care and medical services",
    "department_type": "NURSING",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T10:00:00.000Z"
  },
  "timestamp": "2025-03-17T12:00:00.000Z"
}
```

Use `data.id` as `departmentId` for station endpoints.

### PATCH – Update department

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId`
- Body: JSON. All fields optional; send only what changes.

**Request body example**

```json
{
  "name": "Nursing (Acute Care)",
  "description": "Acute patient care and medical services",
  "department_type": "NURSING",
  "is_active": true,
  "sort_order": 1
}
```

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "organization_id": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
    "name": "Nursing (Acute Care)",
    "code": "NUR",
    "description": "Acute patient care and medical services",
    "department_type": "NURSING",
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:00:00.000Z",
    "updated_at": "2025-03-17T12:05:00.000Z"
  },
  "timestamp": "2025-03-17T12:05:00.000Z"
}
```

### DELETE – Delete department

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Department deleted",
  "data": null,
  "timestamp": "2025-03-17T12:10:00.000Z"
}
```

Deleting a department cascades to its stations, rooms, beds, and chairs, and clears those references on employee-shifts.

---

## Stations

Base path: `/v1/api/organizations/:organizationId/departments/:departmentId/stations`

### GET – List stations

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations`
- Query (optional): `is_active` (boolean), `page` (default 1), `limit` (default 20, max 100)

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "Station A - North Wing",
      "location": "Building 1, Floor 2",
      "code": "NA",
      "required_charge_nurses": 1,
      "required_cnas": 4,
      "required_sitters": 1,
      "required_treatment_nurses": 1,
      "required_nps": 1,
      "required_mds": 1,
      "multi_station_am": false,
      "multi_station_pm": false,
      "multi_station_noc": true,
      "configuration_type": "BEDS",
      "default_beds_per_room": 2,
      "default_chairs_per_room": null,
      "custom_shift_times": null,
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
  "timestamp": "2025-03-17T12:15:00.000Z"
}
```

### GET – Get one station

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId`

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "Station A - North Wing",
    "location": "Building 1, Floor 2",
    "code": "NA",
    "required_charge_nurses": 1,
    "required_cnas": 4,
    "required_sitters": 1,
    "required_treatment_nurses": 1,
    "required_nps": 1,
    "required_mds": 1,
    "multi_station_am": false,
    "multi_station_pm": false,
    "multi_station_noc": true,
    "configuration_type": "BEDS",
    "default_beds_per_room": 2,
    "default_chairs_per_room": null,
    "custom_shift_times": null,
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:10:00.000Z",
    "updated_at": "2025-03-17T10:10:00.000Z",
    "rooms": [
      {
        "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
        "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
        "name": "101",
        "location_or_wing": null,
        "floor": null,
        "configuration_type": "BEDS",
        "beds_per_room": 2,
        "chairs_per_room": null,
        "is_active": true,
        "sort_order": 0,
        "created_at": "2025-03-17T10:15:00.000Z",
        "updated_at": "2025-03-17T10:15:00.000Z",
        "beds": [
          {
            "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
            "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
            "bed_number": "1",
            "is_active": true,
            "created_at": "2025-03-17T10:20:00.000Z",
            "updated_at": "2025-03-17T10:20:00.000Z"
          },
          {
            "id": "a7b8c9d0-e1f2-3456-0123-567890123456",
            "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
            "bed_number": "2",
            "is_active": true,
            "created_at": "2025-03-17T10:20:00.000Z",
            "updated_at": "2025-03-17T10:20:00.000Z"
          }
        ],
        "chairs": []
      }
    ]
  },
  "timestamp": "2025-03-17T12:15:00.000Z"
}
```

### POST – Create station

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations`
- Body: JSON. Only `name` is required. Optionally send `rooms` to create rooms and their beds or chairs in one request.

**Request body (full – no rooms)**

```json
{
  "name": "Station A - North Wing",
  "location": "Building 1, Floor 2",
  "code": "NA",
  "required_charge_nurses": 1,
  "required_cnas": 4,
  "required_sitters": 1,
  "required_treatment_nurses": 1,
  "required_nps": 1,
  "required_mds": 1,
  "multi_station_am": false,
  "multi_station_pm": false,
  "multi_station_noc": true,
  "configuration_type": "BEDS",
  "default_beds_per_room": 2,
  "default_chairs_per_room": null,
  "custom_shift_times": null,
  "is_active": true,
  "sort_order": 1
}
```

**Request body (with bulk rooms – beds)**

```json
{
  "name": "Station A - North Wing",
  "location": "Building 1, Floor 2",
  "required_charge_nurses": 1,
  "required_cnas": 4,
  "required_sitters": 1,
  "required_treatment_nurses": 1,
  "required_nps": 1,
  "required_mds": 1,
  "multi_station_noc": true,
  "configuration_type": "BEDS",
  "default_beds_per_room": 2,
  "rooms": [
    { "name": "101", "beds": 2 },
    { "name": "102", "beds": 2 },
    { "name": "103", "beds": 2 }
  ]
}
```

**Request body (with bulk rooms – chairs)**

```json
{
  "name": "Infusion Station",
  "location": "Building 2, Floor 1",
  "required_charge_nurses": 1,
  "required_cnas": 0,
  "required_sitters": 0,
  "required_treatment_nurses": 2,
  "required_nps": 0,
  "required_mds": 0,
  "configuration_type": "CHAIRS",
  "default_chairs_per_room": 2,
  "rooms": [
    { "name": "1", "chairs": 2 },
    { "name": "2", "chairs": 2 }
  ]
}
```

**Response 201**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "Station A - North Wing",
    "location": "Building 1, Floor 2",
    "code": "NA",
    "required_charge_nurses": 1,
    "required_cnas": 4,
    "required_sitters": 1,
    "required_treatment_nurses": 1,
    "required_nps": 1,
    "required_mds": 1,
    "multi_station_am": false,
    "multi_station_pm": false,
    "multi_station_noc": true,
    "configuration_type": "BEDS",
    "default_beds_per_room": 2,
    "default_chairs_per_room": null,
    "custom_shift_times": null,
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:10:00.000Z",
    "updated_at": "2025-03-17T10:10:00.000Z"
  },
  "timestamp": "2025-03-17T12:20:00.000Z"
}
```

When `rooms` is sent, the server creates the station then creates each room and its beds or chairs; the response is the station only. Use GET station to read back rooms.

### PATCH – Update station

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId`
- Body: JSON. All fields optional.

**Request body example**

```json
{
  "name": "Station A - North Wing (Updated)",
  "location": "Building 1, Floor 2, North",
  "required_charge_nurses": 2,
  "multi_station_noc": true
}
```

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "Station A - North Wing (Updated)",
    "location": "Building 1, Floor 2, North",
    "code": "NA",
    "required_charge_nurses": 2,
    "required_cnas": 4,
    "required_sitters": 1,
    "required_treatment_nurses": 1,
    "required_nps": 1,
    "required_mds": 1,
    "multi_station_am": false,
    "multi_station_pm": false,
    "multi_station_noc": true,
    "configuration_type": "BEDS",
    "default_beds_per_room": 2,
    "default_chairs_per_room": null,
    "custom_shift_times": null,
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:10:00.000Z",
    "updated_at": "2025-03-17T12:25:00.000Z"
  },
  "timestamp": "2025-03-17T12:25:00.000Z"
}
```

### DELETE – Delete station

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Station deleted",
  "data": null,
  "timestamp": "2025-03-17T12:30:00.000Z"
}
```

---

## Rooms

Base path: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms`

### GET – List rooms

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms`
- Query (optional): `is_active` (boolean), `page` (default 1), `limit` (default 20, max 100)

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "name": "101",
      "location_or_wing": "North Wing",
      "floor": "2",
      "configuration_type": "BEDS",
      "beds_per_room": 2,
      "chairs_per_room": null,
      "is_active": true,
      "sort_order": 1,
      "created_at": "2025-03-17T10:15:00.000Z",
      "updated_at": "2025-03-17T10:15:00.000Z"
    },
    {
      "id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "name": "102",
      "location_or_wing": "North Wing",
      "floor": "2",
      "configuration_type": "BEDS",
      "beds_per_room": 2,
      "chairs_per_room": null,
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
  "timestamp": "2025-03-17T12:35:00.000Z"
}
```

### GET – Get one room

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId`

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "name": "101",
    "location_or_wing": "North Wing",
    "floor": "2",
    "configuration_type": "BEDS",
    "beds_per_room": 2,
    "chairs_per_room": null,
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:15:00.000Z",
    "updated_at": "2025-03-17T10:15:00.000Z"
  },
  "timestamp": "2025-03-17T12:35:00.000Z"
}
```

### POST – Create room

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms`
- Body: JSON. Only `name` is required.

**Request body (all fields)**

```json
{
  "name": "101",
  "location_or_wing": "North Wing",
  "floor": "2",
  "configuration_type": "BEDS",
  "beds_per_room": 2,
  "chairs_per_room": null,
  "is_active": true,
  "sort_order": 1
}
```

**Request body (chairs room)**

```json
{
  "name": "Infusion 1",
  "location_or_wing": "East Wing",
  "floor": "1",
  "configuration_type": "CHAIRS",
  "beds_per_room": null,
  "chairs_per_room": 2,
  "is_active": true,
  "sort_order": 1
}
```

**Response 201**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "name": "101",
    "location_or_wing": "North Wing",
    "floor": "2",
    "configuration_type": "BEDS",
    "beds_per_room": 2,
    "chairs_per_room": null,
    "is_active": true,
    "sort_order": 1,
    "created_at": "2025-03-17T10:15:00.000Z",
    "updated_at": "2025-03-17T10:15:00.000Z"
  },
  "timestamp": "2025-03-17T12:40:00.000Z"
}
```

### PATCH – Update room

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId`
- Body: JSON. All fields optional.

**Request body example**

```json
{
  "name": "101-A",
  "location_or_wing": "North Wing",
  "floor": "2",
  "configuration_type": "BEDS",
  "beds_per_room": 2,
  "chairs_per_room": null,
  "is_active": false,
  "sort_order": 1
}
```

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
    "name": "101-A",
    "location_or_wing": "North Wing",
    "floor": "2",
    "configuration_type": "BEDS",
    "beds_per_room": 2,
    "chairs_per_room": null,
    "is_active": false,
    "sort_order": 1,
    "created_at": "2025-03-17T10:15:00.000Z",
    "updated_at": "2025-03-17T12:45:00.000Z"
  },
  "timestamp": "2025-03-17T12:45:00.000Z"
}
```

### DELETE – Delete room

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Room deleted",
  "data": null,
  "timestamp": "2025-03-17T12:50:00.000Z"
}
```

---

## Beds

Base path: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/beds`

### GET – List beds

**Request**

- Method: `GET`
- URL: `.../rooms/:roomId/beds`
- Query (optional): `is_active` (boolean), `page` (default 1), `limit` (default 20, max 100)

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
      "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "bed_number": "1",
      "is_active": true,
      "created_at": "2025-03-17T10:20:00.000Z",
      "updated_at": "2025-03-17T10:20:00.000Z"
    },
    {
      "id": "a7b8c9d0-e1f2-3456-0123-567890123456",
      "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "bed_number": "2",
      "is_active": true,
      "created_at": "2025-03-17T10:20:00.000Z",
      "updated_at": "2025-03-17T10:20:00.000Z"
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

### GET – Get one bed

**Request**

- Method: `GET`
- URL: `.../rooms/:roomId/beds/:bedId`

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_number": "1",
    "is_active": true,
    "created_at": "2025-03-17T10:20:00.000Z",
    "updated_at": "2025-03-17T10:20:00.000Z"
  },
  "timestamp": "2025-03-17T12:55:00.000Z"
}
```

### POST – Create bed

**Request**

- Method: `POST`
- URL: `.../rooms/:roomId/beds`
- Body: JSON. Only `bed_number` is required.

**Request body (full)**

```json
{
  "bed_number": "1",
  "is_active": true
}
```

**Response 201**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_number": "1",
    "is_active": true,
    "created_at": "2025-03-17T10:20:00.000Z",
    "updated_at": "2025-03-17T10:20:00.000Z"
  },
  "timestamp": "2025-03-17T12:55:00.000Z"
}
```

### PATCH – Update bed

**Request**

- Method: `PATCH`
- URL: `.../rooms/:roomId/beds/:bedId`
- Body: JSON. All fields optional.

**Request body example**

```json
{
  "bed_number": "A",
  "is_active": false
}
```

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_number": "A",
    "is_active": false,
    "created_at": "2025-03-17T10:20:00.000Z",
    "updated_at": "2025-03-17T13:00:00.000Z"
  },
  "timestamp": "2025-03-17T13:00:00.000Z"
}
```

### DELETE – Delete bed

**Request**

- Method: `DELETE`
- URL: `.../rooms/:roomId/beds/:bedId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Bed deleted",
  "data": null,
  "timestamp": "2025-03-17T13:05:00.000Z"
}
```

---

## Chairs

Base path: `/v1/api/organizations/:organizationId/departments/:departmentId/stations/:stationId/rooms/:roomId/chairs`

Chairs are used for chair-based rooms (e.g. infusion, dialysis). Structure mirrors beds.

### GET – List chairs

**Request**

- Method: `GET`
- URL: `.../rooms/:roomId/chairs`
- Query (optional): `is_active` (boolean), `page` (default 1), `limit` (default 20, max 100)

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
      "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
      "chair_number": "1",
      "is_active": true,
      "created_at": "2025-03-17T10:25:00.000Z",
      "updated_at": "2025-03-17T10:25:00.000Z"
    },
    {
      "id": "c9d0e1f2-a3b4-5678-2345-789012345678",
      "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
      "chair_number": "2",
      "is_active": true,
      "created_at": "2025-03-17T10:25:00.000Z",
      "updated_at": "2025-03-17T10:25:00.000Z"
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T13:10:00.000Z"
}
```

### GET – Get one chair

**Request**

- Method: `GET`
- URL: `.../rooms/:roomId/chairs/:chairId`

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
    "chair_number": "1",
    "is_active": true,
    "created_at": "2025-03-17T10:25:00.000Z",
    "updated_at": "2025-03-17T10:25:00.000Z"
  },
  "timestamp": "2025-03-17T13:10:00.000Z"
}
```

### POST – Create chair

**Request**

- Method: `POST`
- URL: `.../rooms/:roomId/chairs`
- Body: JSON. Only `chair_number` is required.

**Request body (full)**

```json
{
  "chair_number": "1",
  "is_active": true
}
```

**Response 201**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
    "chair_number": "1",
    "is_active": true,
    "created_at": "2025-03-17T10:25:00.000Z",
    "updated_at": "2025-03-17T10:25:00.000Z"
  },
  "timestamp": "2025-03-17T13:10:00.000Z"
}
```

### PATCH – Update chair

**Request**

- Method: `PATCH`
- URL: `.../rooms/:roomId/chairs/:chairId`
- Body: JSON. All fields optional.

**Request body example**

```json
{
  "chair_number": "A1",
  "is_active": false
}
```

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": {
    "id": "b8c9d0e1-f2a3-4567-1234-678901234567",
    "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
    "chair_number": "A1",
    "is_active": false,
    "created_at": "2025-03-17T10:25:00.000Z",
    "updated_at": "2025-03-17T13:15:00.000Z"
  },
  "timestamp": "2025-03-17T13:15:00.000Z"
}
```

### DELETE – Delete chair

**Request**

- Method: `DELETE`
- URL: `.../rooms/:roomId/chairs/:chairId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Chair deleted",
  "data": null,
  "timestamp": "2025-03-17T13:20:00.000Z"
}
```

---

## Shifts

Base path: `/v1/api/organizations/:organizationId/shifts`

Shifts are organization-level time windows (and optional recurrence). Assignments (who works and where) are in employee-shifts.

### GET – List shifts

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/shifts`
- Query (all optional): `from_date` (YYYY-MM-DD), `to_date` (YYYY-MM-DD), `shift_type`, `status`, `recurrence_type`, `page`, `limit`

**Response 200**

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
      "name": "AM Shift",
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
  "timestamp": "2025-03-17T13:25:00.000Z"
}
```

### GET – Get one shift

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId`

**Response 200**

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
    "name": "AM Shift",
    "status": "ACTIVE",
    "recurrence_type": "FULL_WEEK",
    "recurrence_days": null,
    "recurrence_start_date": "2025-03-17",
    "recurrence_end_date": "2025-03-31",
    "created_at": "2025-03-17T11:00:00.000Z",
    "updated_at": "2025-03-17T11:00:00.000Z"
  },
  "timestamp": "2025-03-17T13:25:00.000Z"
}
```

### POST – Create shift

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/shifts`
- Body: JSON. Required: `start_at`, `end_at` (ISO datetime). Rest optional.

**Request body (one-time)**

```json
{
  "start_at": "2025-03-17T07:00:00.000Z",
  "end_at": "2025-03-17T15:00:00.000Z",
  "shift_type": "DAY",
  "name": "AM Shift"
}
```

**Request body (recurring)**

```json
{
  "start_at": "2025-03-17T07:00:00.000Z",
  "end_at": "2025-03-17T15:00:00.000Z",
  "shift_type": "DAY",
  "name": "AM Shift",
  "recurrence_type": "FULL_WEEK",
  "recurrence_start_date": "2025-03-17",
  "recurrence_end_date": "2025-03-31"
}
```

**Request body (custom days)**

```json
{
  "start_at": "2025-03-17T07:00:00.000Z",
  "end_at": "2025-03-17T15:00:00.000Z",
  "shift_type": "DAY",
  "name": "AM Shift",
  "recurrence_type": "CUSTOM",
  "recurrence_start_date": "2025-03-17",
  "recurrence_end_date": "2025-03-31",
  "recurrence_days": [1, 3, 5]
}
```

`recurrence_days`: 1 = Monday through 7 = Sunday.

**Response 201**

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
    "name": "AM Shift",
    "status": "ACTIVE",
    "recurrence_type": "FULL_WEEK",
    "recurrence_days": null,
    "recurrence_start_date": "2025-03-17",
    "recurrence_end_date": "2025-03-31",
    "created_at": "2025-03-17T11:00:00.000Z",
    "updated_at": "2025-03-17T11:00:00.000Z"
  },
  "timestamp": "2025-03-17T13:25:00.000Z"
}
```

### PATCH – Update shift

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId`
- Body: JSON. All fields optional (e.g. `name`, `status`, `start_at`, `end_at`).

**Request body example**

```json
{
  "name": "AM Shift (Updated)",
  "status": "ACTIVE"
}
```

**Response 200** – Full shift object in `data`, same shape as GET one shift.

### DELETE – Delete shift

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Shift deleted",
  "data": null,
  "timestamp": "2025-03-17T13:30:00.000Z"
}
```

Deleting a shift also deletes all employee-shifts for that shift.

---

## Employee-shifts (assignments)

An employee-shift links one employee to one shift and optionally to a location (department, station, room, and either bed or chair). One employee can appear at most once per shift (duplicate returns 409).

Base path for create/list by shift: `/v1/api/organizations/:organizationId/shifts/:shiftId/employee-shifts`  
Base path for get/update/delete by ID: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`

### GET – List assignments for a shift

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId/employee-shifts`
- Query (optional): `employee_id` (UUID), `status`, `page`, `limit`

**Response 200**

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
      "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "bed_id": "f6a7b8c9-d0e1-2345-f012-456789012345",
      "chair_id": null,
      "status": "SCHEDULED",
      "notes": "Covering for nurse A",
      "actual_start_at": null,
      "actual_end_at": null,
      "created_at": "2025-03-17T11:30:00.000Z",
      "updated_at": "2025-03-17T11:30:00.000Z"
    },
    {
      "id": "d0e1f2a3-b4c5-6789-3456-890123456789",
      "shift_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
      "employee_id": "e1f2a3b4-c5d6-7890-4567-901234567890",
      "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
      "bed_id": null,
      "chair_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
      "status": "SCHEDULED",
      "notes": null,
      "actual_start_at": null,
      "actual_end_at": null,
      "created_at": "2025-03-17T11:35:00.000Z",
      "updated_at": "2025-03-17T11:35:00.000Z"
    }
  ],
  "meta": {
    "total": 2,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2025-03-17T13:35:00.000Z"
}
```

Responses may include nested `employee`, `department`, `station`, `room`, `bed`, `chair` when the API loads relations.

### POST – Create assignment

**Request**

- Method: `POST`
- URL: `/v1/api/organizations/:organizationId/shifts/:shiftId/employee-shifts`
- Body: JSON. Required: `employee_id`. Optional: `department_id`, `station_id`, `room_id`, `bed_id`, `chair_id`, `status`, `notes`. Use either `bed_id` or `chair_id` for a specific bed or chair; do not send both for the same assignment.

**Request body (with bed)**

```json
{
  "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789",
  "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
  "bed_id": "f6a7b8c9-d0e1-2345-f012-456789012345",
  "chair_id": null,
  "status": "SCHEDULED",
  "notes": "Covering for nurse A"
}
```

**Request body (with chair)**

```json
{
  "employee_id": "e1f2a3b4-c5d6-7890-4567-901234567890",
  "department_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "station_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
  "bed_id": null,
  "chair_id": "b8c9d0e1-f2a3-4567-1234-678901234567",
  "status": "SCHEDULED",
  "notes": null
}
```

**Request body (minimal)**

```json
{
  "employee_id": "d0e1f2a3-b4c5-6789-3456-890123456789"
}
```

**Response 201**

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
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "chair_id": null,
    "status": "SCHEDULED",
    "notes": "Covering for nurse A",
    "actual_start_at": null,
    "actual_end_at": null,
    "created_at": "2025-03-17T11:30:00.000Z",
    "updated_at": "2025-03-17T11:30:00.000Z"
  },
  "timestamp": "2025-03-17T13:35:00.000Z"
}
```

### GET – Get one assignment

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`

**Response 200**

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
    "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
    "bed_id": "f6a7b8c9-d0e1-2345-f012-456789012345",
    "chair_id": null,
    "status": "SCHEDULED",
    "notes": "Covering for nurse A",
    "actual_start_at": null,
    "actual_end_at": null,
    "created_at": "2025-03-17T11:30:00.000Z",
    "updated_at": "2025-03-17T11:30:00.000Z"
  },
  "timestamp": "2025-03-17T13:40:00.000Z"
}
```

When relations are loaded, `data` may include nested `shift`, `employee`, `department`, `station`, `room`, `bed`, `chair`.

### PATCH – Update assignment

**Request**

- Method: `PATCH`
- URL: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`
- Body: JSON. All optional: `department_id`, `station_id`, `room_id`, `bed_id`, `chair_id`, `status`, `notes`, `actual_start_at`, `actual_end_at` (ISO strings). Use `null` to clear location fields.

**Request body (clock-in/out and status)**

```json
{
  "status": "COMPLETED",
  "actual_start_at": "2025-03-17T07:05:00.000Z",
  "actual_end_at": "2025-03-17T14:55:00.000Z"
}
```

**Request body (change to a different bed)**

```json
{
  "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
  "bed_id": "a7b8c9d0-e1f2-3456-0123-567890123456",
  "chair_id": null
}
```

**Request body (change to chair)**

```json
{
  "room_id": "e5f6a7b8-c9d0-1234-ef01-345678901234",
  "bed_id": null,
  "chair_id": "b8c9d0e1-f2a3-4567-1234-678901234567"
}
```

**Response 200** – Full employee-shift object in `data`, same shape as GET one assignment.

### DELETE – Remove assignment

**Request**

- Method: `DELETE`
- URL: `/v1/api/organizations/:organizationId/employee-shifts/:employeeShiftId`
- Body: none

**Response 200**

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Employee shift removed",
  "data": null,
  "timestamp": "2025-03-17T13:45:00.000Z"
}
```

---

## Employee’s shifts (by employee)

Convenience endpoint to list all assignments for one employee (e.g. for a personal schedule view).

### GET – List assignments for an employee

**Request**

- Method: `GET`
- URL: `/v1/api/organizations/:organizationId/employees/:employeeId/shifts`
- Query (optional): `from_date` (YYYY-MM-DD), `to_date` (YYYY-MM-DD), `status`, `page`, `limit`

**Response 200**

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
      "room_id": "d4e5f6a7-b8c9-0123-def0-234567890123",
      "bed_id": "f6a7b8c9-d0e1-2345-f012-456789012345",
      "chair_id": null,
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
  "timestamp": "2025-03-17T13:50:00.000Z"
}
```

The API may include the related `shift` (and optionally location entities) in each item.

---

## ID reference

| ID                | Source |
|-------------------|--------|
| `organizationId`  | App state (e.g. after login or org switch). Same for all scheduling calls. |
| `employee_id`     | Your organization’s employees API. Must belong to this org. |
| `departmentId`    | From POST or GET departments. |
| `stationId`       | From POST or GET stations under a department. |
| `roomId`          | From POST or GET rooms under a station. |
| `bedId`           | From POST or GET beds under a room. |
| `chairId`         | From POST or GET chairs under a room. |
| `shiftId`         | From POST or GET shifts. |
| `employeeShiftId` | From POST or GET employee-shifts. |

All location IDs must belong to the same organization; otherwise the API returns 400.

---

## Integration checklist

1. Send `Authorization: Bearer <token>` and `Content-Type: application/json` on every request.
2. Build location hierarchy in order: departments → stations → rooms → then beds or chairs. Use IDs from each create in the next path or body. Optionally create multiple rooms (and their beds/chairs) in one station create via the `rooms` array.
3. Departments list includes `stationCount` per department. Single department GET does not.
4. Station GET one returns nested `rooms` with `beds` and `chairs` when loaded.
5. For shifts, send `start_at` and `end_at` as ISO strings. For recurrence use `recurrence_type` and, for CUSTOM, `recurrence_days` (1–7, Monday–Sunday).
6. When creating an employee-shift, send `employee_id` and optionally `department_id`, `station_id`, `room_id`, and either `bed_id` or `chair_id` (not both). Same employee on the same shift twice returns 409.
7. For an employee’s schedule, GET `.../employees/:employeeId/shifts` with `from_date` and `to_date`.
8. To record clock-in/out or completion, PATCH the employee-shift with `actual_start_at`, `actual_end_at`, and/or `status: "COMPLETED"`.
9. Handle errors using `statusCode` and `message` from the error response.
