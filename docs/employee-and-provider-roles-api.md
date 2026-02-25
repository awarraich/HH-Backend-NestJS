# Employee & Provider Roles API – Request & Response Bodies

Base URL for organization-scoped routes: `GET/POST .../v1/api/organization/:organizationId/...`  
All endpoints require `Authorization: Bearer <JWT>` and organization membership/role as noted.

---

## 1. Get provider roles

**Endpoint:** `GET /v1/api/organization/:organizationId/provider-roles`  
**Auth:** JWT + organization role `OWNER`, `HR`, or `ADMIN`.

Returns all provider roles (e.g. Sitter, RC, LN) for dropdowns/reference.

### Path parameters

| Name             | Type   | Description        |
|------------------|--------|--------------------|
| `organizationId` | string | Organization UUID  |

### Request body

None.

### Response body (200 OK)

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation successful",
  "data": [
    {
      "id": "uuid",
      "code": "SITTER",
      "name": "Sitter",
      "description": "Sitter role description or null",
      "created_at": "2026-02-24T12:00:00.000Z"
    },
    {
      "id": "uuid",
      "code": "RC",
      "name": "RC",
      "description": null,
      "created_at": "2026-02-24T12:00:00.000Z"
    }
  ],
  "timestamp": "2026-02-24T12:00:00.000Z"
}
```

---

## 2. Create employee by email

**Endpoint:** `POST /v1/api/organization/:organizationId/employee/by-email`  
**Auth:** JWT + organization role `OWNER` or `HR`.

Creates a user (with temporary password) and an employee + profile for that organization. Sends an email with the temporary password. Only assign system role **EMPLOYEE**; job role is represented by **provider_role_id** (from provider roles), not job roles like ADMIN/PROVIDER/STAFF/HR.

### Path parameters

| Name             | Type   | Description       |
|------------------|--------|-------------------|
| `organizationId` | string | Organization UUID |

### Request body

All fields except `email`, `firstName`, and `lastName` are optional.

| Field                 | Type   | Required | Description |
|-----------------------|--------|----------|-------------|
| `email`               | string | Yes      | Valid email; user must not already exist |
| `firstName`           | string | Yes      | Max 255 |
| `lastName`            | string | Yes      | Max 255 |
| `phone_number`        | string | No       | Max 20 |
| `gender`              | string | No       | One of: `MALE`, `FEMALE`, `OTHER`, `PREFER_NOT_TO_SAY` |
| `date_of_birth`       | string | No       | ISO 8601 date |
| `address`             | string | No       | Profile address |
| `provider_role_id`    | string | No       | UUID from provider_roles (e.g. Sitter, RC, LN) |
| `specialization`      | string | No       | Max 100 |
| `years_of_experience` | number | No       | 0–100 |
| `certification`       | string | No       | Max 100 |
| `board_certifications`| object | No       | Key-value object |
| `employment_type`     | string | No       | One of: `FULL_TIME`, `PART_TIME`, `CONTRACT`, `PER_DIEM` |
| `status`              | string | No       | One of: `ACTIVE`, `INACTIVE`, `INVITED`, `TERMINATED`. Default: `ACTIVE` |
| `start_date`          | string | No       | ISO 8601 date. Default: today |
| `end_date`            | string | No       | ISO 8601 date |
| `department`          | string | No       | Max 100 |
| `position_title`      | string | No       | Max 100 |
| `notes`               | string | No       | Free text |

**Example request body:**

```json
{
  "email": "jane.doe@example.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "phone_number": "+1234567890",
  "provider_role_id": "uuid-of-sitter-role",
  "employment_type": "FULL_TIME",
  "status": "ACTIVE",
  "department": "Nursing",
  "position_title": "Sitter"
}
```

### Response body (201 Created)

```json
{
  "success": true,
  "statusCode": 201,
  "message": "Employee created. An email with temporary password has been sent.",
  "data": {
    "id": "employee-uuid",
    "user_id": "user-uuid",
    "organization_id": "organization-uuid",
    "status": "ACTIVE",
    "employment_type": "FULL_TIME",
    "notes": null,
    "provider_role_id": "provider-role-uuid",
    "start_date": "2026-02-24",
    "end_date": null,
    "department": "Nursing",
    "position_title": "Sitter",
    "created_at": "2026-02-24T12:00:00.000Z",
    "updated_at": "2026-02-24T12:00:00.000Z",
    "user": {
      "id": "user-uuid",
      "email": "jane.doe@example.com",
      "firstName": "Jane",
      "lastName": "Doe",
      "is_active": true
    },
    "organization": {
      "id": "organization-uuid",
      "organization_name": "Acme Care"
    },
    "profile": {
      "id": "profile-uuid",
      "employee_id": "employee-uuid",
      "name": "Jane Doe",
      "profile_image": null,
      "address": null,
      "phone_number": "+1234567890",
      "gender": null,
      "age": null,
      "date_of_birth": null,
      "specialization": null,
      "years_of_experience": null,
      "certification": null,
      "board_certifications": null,
      "emergency_contact": null,
      "created_at": "2026-02-24T12:00:00.000Z",
      "updated_at": "2026-02-24T12:00:00.000Z"
    },
    "provider_role": {
      "id": "provider-role-uuid",
      "code": "SITTER",
      "name": "Sitter"
    }
  },
  "timestamp": "2026-02-24T12:00:00.000Z"
}
```

### Error responses

- **400** – Validation errors (e.g. invalid email, invalid enum).
- **403** – User does not have OWNER/HR in the organization.
- **404** – Organization not found.
- **409** – User with this email already exists (use add-by-user-id flow instead).

---

## 3. List employees by organization

**Endpoint:** `GET /v1/api/organization/:organizationId/employee`  
**Auth:** JWT + organization role `OWNER`, `HR`, or `ADMIN`.

Returns a paginated list of employees for the organization. Supports search and filters.

### Path parameters

| Name             | Type   | Description       |
|------------------|--------|-------------------|
| `organizationId` | string | Organization UUID |

### Query parameters

| Name              | Type   | Required | Description |
|-------------------|--------|----------|-------------|
| `search`          | string | No       | Search in department, position title, user first/last name, email (case-insensitive) |
| `provider_role_id` | string | No     | Filter by provider role UUID |
| `status`          | string | No       | One of: `ACTIVE`, `INVITED`, `INACTIVE`, `TERMINATED` |
| `page`            | number | No       | Page number (default: 1) |
| `limit`           | number | No       | Items per page 1–100 (default: 20) |

### Request body

None.

### Response body (200 OK)

```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "employee-uuid",
      "user_id": "user-uuid",
      "organization_id": "organization-uuid",
      "status": "ACTIVE",
      "employment_type": "FULL_TIME",
      "notes": null,
      "provider_role_id": "provider-role-uuid",
      "start_date": "2026-02-24",
      "end_date": null,
      "department": "Nursing",
      "position_title": "Sitter",
      "created_at": "2026-02-24T12:00:00.000Z",
      "updated_at": "2026-02-24T12:00:00.000Z",
      "user": {
        "id": "user-uuid",
        "email": "jane.doe@example.com",
        "firstName": "Jane",
        "lastName": "Doe",
        "is_active": true
      },
      "organization": {
        "id": "organization-uuid",
        "organization_name": "Acme Care"
      },
      "profile": { ... },
      "provider_role": {
        "id": "provider-role-uuid",
        "code": "SITTER",
        "name": "Sitter"
      }
    }
  ],
  "meta": {
    "total": 42,
    "page": 1,
    "limit": 20,
    "totalPages": 3
  },
  "timestamp": "2026-02-24T12:00:00.000Z"
}
```

### Error responses

- **404** – Organization not found.

---

## 4. Delete employee

**Endpoint:** `DELETE /v1/api/organization/:organizationId/employee/:id`  
**Auth:** JWT + organization role `OWNER` or `HR`.

Permanently removes the employee and their profile from the organization. The user account is not deleted. All related employee data (employee record and employee profile) is deleted in a single transaction.

### Path parameters

| Name             | Type   | Description       |
|------------------|--------|-------------------|
| `organizationId` | string | Organization UUID |
| `id`             | string | Employee UUID     |

### Request body

None.

### Response body (200 OK)

```json
{
  "success": true,
  "statusCode": 200,
  "message": "Employee removed successfully",
  "data": null,
  "timestamp": "2026-02-24T12:00:00.000Z"
}
```

### Error responses

- **403** – User does not have OWNER/HR in the organization.
- **404** – Employee not found in this organization.
