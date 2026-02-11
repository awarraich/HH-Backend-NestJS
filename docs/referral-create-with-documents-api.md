# Create Referral with Documents (single request)

Create a referral and upload document files in **one** multipart request.

## Endpoint

```
POST /v1/api/organization/:organizationId/referrals/with-documents
```

- **Auth:** Bearer token required (same as other referral endpoints).
- **Content-Type:** `multipart/form-data`.

## Form parts

| Part type | Field name | Required | Description |
|-----------|------------|----------|-------------|
| Field     | `data`     | Yes      | JSON **string** of the referral payload (see below). Can be in any position; server processes parts in stream order. |
| File      | `documents`| No       | One or more files. Use the same field name `documents` for each file. |

## Referral payload (JSON inside `data`)

Same shape as the JSON create-referral body, **without** the `documents` array (the API adds it from the uploaded files):

```json
{
  "patient_id": "uuid-of-patient",
  "organization_type_id": 1,
  "receiving_organization_ids": ["uuid-1", "uuid-2"],
  "urgency": "urgent",
  "notes": "Referral notes...",
  "insurance_provider": "Optional",
  "estimated_cost": "Optional",
  "level_of_care": "Optional"
}
```

Or with inline patient (no `patient_id`):

```json
{
  "patient": {
    "name": "John Doe",
    "date_of_birth": "1990-01-15",
    "address": "123 Main St",
    "primary_insurance_provider": "Acme Insurance"
  },
  "organization_type_id": 1,
  "receiving_organization_ids": ["uuid-1"],
  "urgency": "urgent",
  "notes": "Notes..."
}
```

Do **not** include `documents` in the JSON; the server fills it from the uploaded files.

## Frontend usage

### JavaScript / fetch

```javascript
const organizationId = 'your-org-uuid';
const token = 'your-jwt';

const referralPayload = {
  patient_id: 'patient-uuid',
  organization_type_id: 1,
  receiving_organization_ids: ['receiver-org-uuid'],
  urgency: 'urgent',
  notes: 'Patient needs home health follow-up.',
};

const formData = new FormData();
// Important: append "data" first so it’s the first part
formData.append('data', JSON.stringify(referralPayload));

// Append each file with the same field name "documents"
for (const file of selectedFiles) {
  formData.append('documents', file);
}

const response = await fetch(
  `${API_BASE}/v1/api/organization/${organizationId}/referrals/with-documents`,
  {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      // Do NOT set Content-Type; browser sets it with boundary for FormData
    },
    body: formData,
  }
);

const result = await response.json();
if (result.success) {
  console.log('Referral created:', result.data);
}
```

### React example (with state)

```jsx
const [payload, setPayload] = useState({
  patient_id: '',
  organization_type_id: 1,
  receiving_organization_ids: [],
  urgency: 'urgent',
  notes: '',
});
const [files, setFiles] = useState([]);

const handleSubmit = async (e) => {
  e.preventDefault();
  const formData = new FormData();
  formData.append('data', JSON.stringify(payload));
  files.forEach((file) => formData.append('documents', file));

  const res = await fetch(
    `${API_BASE}/v1/api/organization/${organizationId}/referrals/with-documents`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    }
  );
  const data = await res.json();
  if (data.success) {
    // Redirect or show success
  }
};
```

### cURL

```bash
curl -X POST "http://localhost:3000/v1/api/organization/YOUR_ORG_ID/referrals/with-documents" \
  -H "Authorization: Bearer YOUR_JWT" \
  -F "data={\"patient_id\":\"PATIENT_UUID\",\"organization_type_id\":1,\"receiving_organization_ids\":[\"ORG_UUID\"],\"urgency\":\"urgent\",\"notes\":\"Notes\"}" \
  -F "documents=@/path/to/file1.pdf" \
  -F "documents=@/path/to/file2.pdf"
```

## Response

Same as the standard create-referral response:

```json
{
  "success": true,
  "statusCode": 201,
  "message": "Referral created successfully",
  "data": {
    "id": "...",
    "public_id": "REF-003",
    "status": "pending",
    "documents": [
      { "id": "...", "file_name": "file1.pdf", "file_url": "...", "created_at": "..." }
    ],
    ...
  }
}
```

## Errors

- **400** – Missing or invalid `data` field, invalid JSON, or validation errors (e.g. missing required fields).
- **401** – Unauthorized (invalid or missing token).
- **403** – Forbidden (user not in organization or no permission).

## Alternative: JSON create + separate uploads

You can still:

1. Upload files with `POST .../referrals/documents/upload` (one call per file).
2. Create the referral with `POST .../referrals` (JSON body) and pass the returned `file_name` and `file_url` in the `documents` array.

Use **with-documents** when you want a single request that includes both referral data and files.
