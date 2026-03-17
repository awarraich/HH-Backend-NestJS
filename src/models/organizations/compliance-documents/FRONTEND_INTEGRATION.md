# Company Documents & Compliance — Frontend Integration Guide

**Base URL:** `{{API_URL}}/v1/api/organizations/:organizationId/compliance`

**Auth:** All endpoints require `Authorization: Bearer <jwt-token>` header.

**Roles:** `OWNER`, `HR`, `MANAGER`

---

## 1. CATEGORY ENDPOINTS

Base: `/compliance/categories`

---

### 1.1 List All Categories

**Used by:** Category tabs, category dropdown in "Add Document" form

```
GET /compliance/categories
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "categories": [
      {
        "id": "uuid",
        "organization_id": "uuid",
        "name": "Business License",
        "description": "State and local business licenses",
        "icon": "💼",
        "color": "#3B82F6",
        "sort_order": 0,
        "is_active": true,
        "is_default": false,
        "document_count": 2,
        "created_at": "2026-03-17T10:00:00.000Z",
        "updated_at": "2026-03-17T10:00:00.000Z"
      }
    ],
    "total": 8
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

---

### 1.2 Get Single Category

```
GET /compliance/categories/:id
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "id": "uuid",
    "organization_id": "uuid",
    "name": "Business License",
    "description": "State and local business licenses",
    "icon": "💼",
    "color": "#3B82F6",
    "sort_order": 0,
    "is_active": true,
    "is_default": false,
    "document_count": 2,
    "created_at": "2026-03-17T10:00:00.000Z",
    "updated_at": "2026-03-17T10:00:00.000Z"
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

---

### 1.3 Create Category

**Used by:** "Add Category" modal

```
POST /compliance/categories
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Survey Reports",
  "description": "Annual and periodic survey reports",
  "icon": "📊",
  "color": "#10B981"
}
```

| Field         | Type   | Required | Notes                    |
|---------------|--------|----------|--------------------------|
| `name`        | string | Yes      | Max 255 chars            |
| `description` | string | No       |                          |
| `icon`        | string | No       | Emoji, max 50 chars      |
| `color`       | string | No       | Hex color, max 20 chars  |

**Response (201):**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Category created successfully",
  "data": {
    "id": "uuid",
    "organization_id": "uuid",
    "name": "Survey Reports",
    "description": "Annual and periodic survey reports",
    "icon": "📊",
    "color": "#10B981",
    "sort_order": 0,
    "is_active": true,
    "is_default": false,
    "document_count": 0,
    "created_at": "2026-03-17T10:00:00.000Z",
    "updated_at": "2026-03-17T10:00:00.000Z"
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

**Error (400):**
```json
{
  "success": false,
  "statusCode": 400,
  "message": "A category with this name already exists"
}
```

---

### 1.4 Update Category

**Used by:** "Edit Category" modal

```
PATCH /compliance/categories/:id
Content-Type: application/json
```

**Request Body (all fields optional):**
```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "icon": "🛡️",
  "color": "#EF4444",
  "sort_order": 1,
  "is_active": true
}
```

| Field        | Type    | Required | Notes            |
|--------------|---------|----------|------------------|
| `name`       | string  | No       | Max 255 chars    |
| `description`| string  | No       |                  |
| `icon`       | string  | No       | Max 50 chars     |
| `color`      | string  | No       | Max 20 chars     |
| `sort_order` | integer | No       | Min 0            |
| `is_active`  | boolean | No       |                  |

**Response:** Same shape as Create.

---

### 1.5 Delete Category

**Used by:** "Delete Category" button

```
DELETE /compliance/categories/:id
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Category deleted successfully",
  "data": null,
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

**Error (400) — category has documents:**
```json
{
  "success": false,
  "statusCode": 400,
  "message": "Cannot delete a category that has documents. Move or delete documents first."
}
```

---

## 2. DOCUMENT ENDPOINTS

Base: `/compliance/documents`

---

### 2.1 List Documents (Paginated + Filterable)

**Used by:** Main document table, category tab filtering, status filtering

```
GET /compliance/documents?search=&category_id=&status=&sort_by=&sort_order=&page=&limit=
```

**Query Parameters:**

| Param        | Type   | Default      | Options                                              |
|-------------|--------|--------------|------------------------------------------------------|
| `search`     | string | —            | Search by document name (ILIKE)                      |
| `category_id`| uuid   | —            | Filter by category                                   |
| `status`     | string | —            | `valid`, `expired`, `expiring_soon`, `missing`       |
| `sort_by`    | string | `created_at` | `category`, `document_name`, `expiration_date`, `created_at` |
| `sort_order` | string | `desc`       | `asc`, `desc`                                        |
| `page`       | int    | 1            | Min 1                                                |
| `limit`      | int    | 20           | Min 1, Max 100                                       |

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": [
    {
      "id": "uuid",
      "organization_id": "uuid",
      "document_name": "State Business License",
      "file_name": "state-business-license.pdf",
      "file_size_bytes": 245000,
      "mime_type": "application/pdf",
      "is_required": true,
      "has_expiration": true,
      "expiration_date": "2026-01-14",
      "expiration_reminder_days": 90,
      "status": "expired",
      "days_until_expiration": -61,
      "extraction_status": "completed",
      "created_at": "2026-03-15T10:00:00.000Z",
      "updated_at": "2026-03-15T10:00:00.000Z",
      "category": {
        "id": "uuid",
        "name": "Business License",
        "icon": "💼",
        "color": "#3B82F6"
      },
      "uploaded_by": {
        "id": "uuid",
        "name": "John Doe"
      }
    }
  ],
  "meta": {
    "total": 10,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

**Document `status` values:**

| Status          | Meaning                                      | UI Badge    |
|-----------------|----------------------------------------------|-------------|
| `valid`         | Has expiration, not expired, not expiring soon | Green       |
| `expired`       | Has expiration, past expiration date          | Red         |
| `expiring_soon` | Has expiration, within reminder window        | Orange      |
| `no_expiration` | No expiration date set                        | No badge    |

**When filtering by `status=missing`**, it returns documents with `no_expiration` status.

---

### 2.2 Get Document Stats

**Used by:** Dashboard stat cards (Total, Valid, Expiring Soon, Expired, Missing)

```
GET /compliance/documents/stats
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "total": 10,
    "valid": 2,
    "expiring_soon": 0,
    "expired": 4,
    "missing": 4,
    "by_category": [
      { "category_id": "uuid", "category_name": "Business License", "count": 2 },
      { "category_id": "uuid", "category_name": "Insurance", "count": 2 },
      { "category_id": "uuid", "category_name": "Certifications", "count": 1 },
      { "category_id": "uuid", "category_name": "CLIA", "count": 1 },
      { "category_id": "uuid", "category_name": "Committee Documents", "count": 1 },
      { "category_id": "uuid", "category_name": "Employee Records", "count": 1 },
      { "category_id": "uuid", "category_name": "Policy & Procedures", "count": 1 },
      { "category_id": "uuid", "category_name": "Survey Reports", "count": 1 }
    ]
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

---

### 2.3 Get Single Document

**Used by:** Document detail view

```
GET /compliance/documents/:documentId
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "id": "uuid",
    "organization_id": "uuid",
    "document_name": "State Business License",
    "file_name": "state-business-license.pdf",
    "file_size_bytes": 245000,
    "mime_type": "application/pdf",
    "is_required": true,
    "has_expiration": true,
    "expiration_date": "2026-01-14",
    "expiration_reminder_days": 90,
    "status": "expired",
    "days_until_expiration": -61,
    "extraction_status": "completed",
    "created_at": "2026-03-15T10:00:00.000Z",
    "updated_at": "2026-03-15T10:00:00.000Z",
    "category": {
      "id": "uuid",
      "name": "Business License",
      "icon": "💼",
      "color": "#3B82F6"
    },
    "uploaded_by": {
      "id": "uuid",
      "name": "John Doe"
    }
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

---

### 2.4 Upload Document

**Used by:** "Add Document" modal

```
POST /compliance/documents
Content-Type: multipart/form-data
```

**Form Fields:**

| Field             | Type    | Required | Notes                                  |
|-------------------|---------|----------|----------------------------------------|
| `file`            | File    | Yes      | PDF, DOCX, PNG, JPG allowed            |
| `document_name`   | string  | Yes      | e.g. "State Business License"          |
| `category_id`     | uuid    | Yes      | Must be an existing category           |
| `is_required`     | string  | No       | `"true"` or `"false"` (default false)  |
| `has_expiration`   | string  | No       | `"true"` or `"false"` (default false)  |
| `expiration_date`  | string  | No       | ISO date `"2026-01-14"` (when has_expiration is true) |

**Example (JavaScript FormData):**
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('document_name', 'State Business License');
formData.append('category_id', 'category-uuid');
formData.append('is_required', 'true');
formData.append('has_expiration', 'true');
formData.append('expiration_date', '2026-01-14');

await fetch(`${API_URL}/v1/api/organizations/${orgId}/compliance/documents`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}` },
  body: formData,
});
```

**Response (201):**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Document uploaded successfully",
  "data": {
    "id": "uuid",
    "organization_id": "uuid",
    "document_name": "State Business License",
    "file_name": "state-business-license.pdf",
    "file_size_bytes": 245000,
    "mime_type": "application/pdf",
    "is_required": true,
    "has_expiration": true,
    "expiration_date": "2026-01-14",
    "expiration_reminder_days": 90,
    "status": "expired",
    "days_until_expiration": -61,
    "extraction_status": "pending",
    "created_at": "2026-03-17T10:00:00.000Z",
    "updated_at": "2026-03-17T10:00:00.000Z",
    "category": {
      "id": "uuid",
      "name": "Business License",
      "icon": "💼",
      "color": "#3B82F6"
    },
    "uploaded_by": {
      "id": "uuid",
      "name": "John Doe"
    }
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

> Note: `extraction_status` starts as `"pending"`. The backend processes the file in the background (extracts text, creates vector embeddings). It will change to `"completed"` or `"failed"`.

---

### 2.5 Update Document Metadata

**Used by:** "Edit Document" modal

```
PATCH /compliance/documents/:documentId
Content-Type: application/json
```

**Request Body (all fields optional):**
```json
{
  "document_name": "Updated License Name",
  "category_id": "new-category-uuid",
  "is_required": true,
  "has_expiration": true,
  "expiration_date": "2027-01-14"
}
```

| Field             | Type         | Required | Notes                        |
|-------------------|--------------|----------|------------------------------|
| `document_name`   | string       | No       | Max 255 chars                |
| `category_id`     | uuid         | No       | Must exist                   |
| `is_required`     | boolean      | No       |                              |
| `has_expiration`   | boolean      | No       |                              |
| `expiration_date`  | string/null  | No       | ISO date or null to clear    |

**Response:** Same document shape as Upload.

---

### 2.6 Replace Document File

**Used by:** "Replace" button on document row

```
POST /compliance/documents/:documentId/replace
Content-Type: multipart/form-data
```

**Form Fields:**

| Field  | Type | Required | Notes                       |
|--------|------|----------|-----------------------------|
| `file` | File | Yes      | PDF, DOCX, PNG, JPG allowed |

**Response:** Same document shape as Upload. `extraction_status` resets to `"pending"`.

---

### 2.7 Delete Document

**Used by:** "Delete Document" button

```
DELETE /compliance/documents/:documentId
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Document deleted successfully",
  "data": null,
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

---

### 2.8 Download Document File

**Used by:** "Download" button

```
GET /compliance/documents/:documentId/download
```

**Response:** Binary file stream with headers:
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="state-business-license.pdf"
```

**Example:**
```javascript
const response = await fetch(
  `${API_URL}/v1/api/organizations/${orgId}/compliance/documents/${docId}/download`,
  { headers: { Authorization: `Bearer ${token}` } }
);
const blob = await response.blob();
const url = URL.createObjectURL(blob);
// trigger download
```

---

### 2.9 View Document File (Inline)

**Used by:** "View" button / document preview

```
GET /compliance/documents/:documentId/view
```

**Response:** Binary file stream with headers:
```
Content-Type: application/pdf
Content-Disposition: inline; filename="state-business-license.pdf"
```

**Example (open in new tab or iframe):**
```javascript
window.open(
  `${API_URL}/v1/api/organizations/${orgId}/compliance/documents/${docId}/view`,
  '_blank'
);
```

---

## 3. AI ENDPOINTS

Base: `/compliance/documents`

---

### 3.1 AI Scan Document

**Used by:** "AI Scan" button on each document row

Triggers text extraction from the file + chunking + vector embedding. Run this before using search or chat on a document.

```
POST /compliance/documents/:documentId/scan
```

**Request Body:** None

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Document scanned successfully",
  "data": {
    "extraction_status": "completed",
    "chunk_count": 12
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

| `extraction_status` | Meaning                             |
|---------------------|-------------------------------------|
| `completed`         | Text extracted and embedded          |
| `failed`            | Extraction failed (check logs)       |

> Note: Scanning also happens automatically on upload. This endpoint is for re-scanning or manually triggering.

---

### 3.2 Semantic Search

**Used by:** Search bar on documents page

```
POST /compliance/documents/search
Content-Type: application/json
```

**Request Body:**
```json
{
  "query": "infection control hand hygiene policy",
  "category_id": "optional-category-uuid",
  "limit": 10
}
```

| Field         | Type    | Required | Notes              |
|---------------|---------|----------|--------------------|
| `query`       | string  | Yes      | Natural language    |
| `category_id` | uuid    | No       | Restrict to category |
| `limit`       | integer | No       | 1-20, default 10   |

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "results": [
      {
        "document_id": "uuid",
        "document_name": "Policy: Infection Control",
        "category_name": "Policy & Procedures",
        "snippet": "All staff must follow standard precautions including hand hygiene protocols when entering and exiting patient rooms...",
        "similarity_score": 0.92,
        "chunk_index": 3
      }
    ],
    "total_results": 1
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

---

### 3.3 AI Chat (General Compliance Assistant)

**Used by:** "AI Assistant" chat widget on the compliance page

The LLM autonomously decides which tools to use based on the user's question. Supports multi-turn conversation via `history`.

```
POST /compliance/documents/chat
Content-Type: application/json
```

**Request Body:**
```json
{
  "message": "What documents are expiring soon?",
  "history": [
    { "role": "user", "content": "Show me our compliance overview" },
    { "role": "assistant", "content": "You have 10 total documents..." }
  ],
  "document_ids": []
}
```

| Field          | Type   | Required | Notes                                          |
|----------------|--------|----------|-------------------------------------------------|
| `message`      | string | Yes      | The user's current message                      |
| `history`      | array  | No       | Previous conversation turns                      |
| `history[].role`   | string | Yes  | `"user"` or `"assistant"`                        |
| `history[].content`| string | Yes  | The message content                              |
| `document_ids` | uuid[] | No       | Scope chat to specific documents (for single-doc chat) |

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "message": "You have 4 documents that are expired and need immediate attention:\n\n1. **CLIA Certificate** — expired 492 days ago (Nov 9, 2024)\n2. **General Liability Insurance** — expired 381 days ago (Feb 28, 2025)\n3. **Certificate of Insurance - Vendor** — expired 275 days ago (Jun 14, 2025)\n4. **State Business License** — expired 61 days ago (Jan 14, 2026)\n\nNo documents are expiring in the next 90 days. I recommend prioritizing the CLIA Certificate renewal first.",
    "sources": [
      {
        "document_id": "uuid",
        "document_name": "CLIA Certificate",
        "file_name": "clia-cert.pdf",
        "snippet": "Certificate of Compliance... Expiration Date: 11/09/2024..."
      }
    ]
  },
  "timestamp": "2026-03-17T10:00:00.000Z"
}
```

**Tools the LLM can call internally (frontend does NOT see these):**

| Tool | When LLM uses it |
|------|------------------|
| `list_compliance_documents` | "Show me all documents", "List expired docs" |
| `get_compliance_stats` | "How's our compliance?", "Overview" |
| `get_compliance_document_details` | "Tell me about the CLIA cert" |
| `search_compliance_documents` | "What does our infection control policy say?" |
| `get_expiring_documents_alert` | "What needs attention?", "Any overdue?" |
| `analyze_compliance_document` | "Analyze the insurance doc", "Extract key terms" |
| `compare_compliance_documents` | "Compare our two insurance policies" |

---

### 3.3a AI Chat — Single Document Mode

**Used by:** Chat widget when viewing a specific document

Same endpoint, just pass the document ID to scope the conversation.
When `document_ids` is provided, the AI automatically:
- Knows which document you're asking about (by name and ID)
- Uses only document-relevant tools (details, search within doc, analyze)
- Never asks "which document?" — it already knows
- Scopes semantic search to only that document's content

```json
{
  "message": "What is the expiration date?",
  "document_ids": ["uuid-of-specific-document"],
  "history": []
}
```

**Response:**
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "message": "The CLIA Certificate expired on November 9, 2024. It has been expired for 492 days and requires immediate renewal.",
    "sources": [
      {
        "document_id": "uuid",
        "document_name": "CLIA Certificate",
        "file_name": "clia-cert.pdf",
        "snippet": "Certificate of Compliance... Expiration Date: 11/09/2024..."
      }
    ]
  }
}
```

**Multi-turn example:**
```javascript
// First message
await api.post('/compliance/documents/chat', {
  message: "What is this document about?",
  document_ids: ["2ee10e4e-826d-462b-8a18-a83495a77b1c"],
  history: [],
});

// Follow-up message
await api.post('/compliance/documents/chat', {
  message: "When does it expire?",
  document_ids: ["2ee10e4e-826d-462b-8a18-a83495a77b1c"],
  history: [
    { role: "user", content: "What is this document about?" },
    { role: "assistant", content: "This is a CLIA Certificate of Compliance..." }
  ],
});
```

---

## 4. UI → ENDPOINT MAPPING

### Document List Page

| UI Element                  | Endpoint                            | When                    |
|-----------------------------|-------------------------------------|-------------------------|
| Stats cards (Total/Valid/Expired/etc.) | `GET /documents/stats`       | Page load               |
| Document table              | `GET /documents`                     | Page load + filter change |
| Category tabs               | `GET /categories`                    | Page load               |
| Click category tab          | `GET /documents?category_id=uuid`    | Tab click               |
| Filter by status            | `GET /documents?status=expired`      | Status filter change    |
| Sort by column              | `GET /documents?sort_by=category&sort_order=asc` | Column header click |
| Search bar (text)           | `GET /documents?search=CLIA`         | Search input            |
| Search bar (semantic/AI)    | `POST /documents/search`             | Semantic search toggle  |
| Pagination                  | `GET /documents?page=2&limit=20`     | Page change             |

### Add Document Modal

| UI Element           | Endpoint                              | When           |
|----------------------|---------------------------------------|----------------|
| Category dropdown    | `GET /categories`                      | Modal open     |
| Submit form          | `POST /documents` (multipart)          | Form submit    |

### Add Category Modal

| UI Element | Endpoint           | When        |
|------------|--------------------|-------------|
| Submit     | `POST /categories` | Form submit |

### Document Row Actions

| Button     | Endpoint                                | Notes                     |
|------------|-----------------------------------------|---------------------------|
| View       | `GET /documents/:id/view`               | Opens in new tab/iframe   |
| Download   | `GET /documents/:id/download`           | Triggers file download    |
| AI Scan    | `POST /documents/:id/scan`              | Extracts text + embeddings |
| Replace    | `POST /documents/:id/replace` (multipart) | Replaces file only     |
| Edit       | `PATCH /documents/:id`                  | Updates metadata          |
| Delete     | `DELETE /documents/:id`                 | Soft deletes              |

### Edit Document Modal

| UI Element | Endpoint              | When        |
|------------|-----------------------|-------------|
| Load data  | `GET /documents/:id`  | Modal open  |
| Submit     | `PATCH /documents/:id`| Form submit |

### Edit Category Modal

| UI Element | Endpoint                  | When        |
|------------|---------------------------|-------------|
| Load data  | `GET /categories/:id`     | Modal open  |
| Submit     | `PATCH /categories/:id`   | Form submit |

### AI Assistant Widget

| UI Element         | Endpoint                  | When                      |
|--------------------|---------------------------|---------------------------|
| Send message       | `POST /documents/chat`    | User sends chat message   |
| Multi-turn chat    | `POST /documents/chat` with `history` | Each subsequent message |

---

## 5. FRONTEND STATE MANAGEMENT SUGGESTIONS

### Chat History (for multi-turn)

```javascript
const [chatHistory, setChatHistory] = useState([]);

async function sendMessage(message) {
  // Add user message to history
  const newHistory = [...chatHistory, { role: 'user', content: message }];

  const response = await api.post(`/compliance/documents/chat`, {
    message,
    history: chatHistory, // send previous turns (not including current)
    document_ids: scopedDocumentIds || undefined,
  });

  // Add assistant response to history
  setChatHistory([
    ...newHistory,
    { role: 'assistant', content: response.data.data.message },
  ]);
}
```

### Status Badge Component

```javascript
function StatusBadge({ status, daysUntilExpiration }) {
  switch (status) {
    case 'valid':
      return <Badge color="green">Valid</Badge>;
    case 'expired':
      return <Badge color="red">Expired</Badge>;
    case 'expiring_soon':
      return <Badge color="orange">Expiring Soon</Badge>;
    case 'no_expiration':
      return null; // no badge
  }
}

function ExpirationWarning({ status, daysUntilExpiration }) {
  if (status === 'expired') {
    return <span>⚠ Action required: Expired {Math.abs(daysUntilExpiration)} days ago</span>;
  }
  if (status === 'expiring_soon' || status === 'valid') {
    return <span>⚠ Action required: Expires in {daysUntilExpiration} days</span>;
  }
  return null;
}
```

### File Upload

```javascript
async function uploadDocument(file, formValues) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('document_name', formValues.document_name);
  formData.append('category_id', formValues.category_id);
  formData.append('is_required', String(formValues.is_required));
  formData.append('has_expiration', String(formValues.has_expiration));
  if (formValues.has_expiration && formValues.expiration_date) {
    formData.append('expiration_date', formValues.expiration_date);
  }

  return api.post(`/compliance/documents`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
}
```

---

## 6. ERROR RESPONSES

All errors follow this format:

```json
{
  "success": false,
  "statusCode": 400,
  "message": "Error description here"
}
```

| Status | Meaning                          |
|--------|----------------------------------|
| 400    | Validation error / bad request   |
| 401    | Not authenticated                |
| 403    | Not authorized (wrong role)      |
| 404    | Document/category not found      |
| 500    | Internal server error            |

---

## 7. COMPLETE ENDPOINT REFERENCE

| #  | Method   | Path                                    | Purpose                    |
|----|----------|-----------------------------------------|----------------------------|
| 1  | `GET`    | `/compliance/categories`                | List all categories        |
| 2  | `GET`    | `/compliance/categories/:id`            | Get single category        |
| 3  | `POST`   | `/compliance/categories`                | Create category            |
| 4  | `PATCH`  | `/compliance/categories/:id`            | Update category            |
| 5  | `DELETE` | `/compliance/categories/:id`            | Delete category            |
| 6  | `GET`    | `/compliance/documents`                 | List documents (paginated) |
| 7  | `GET`    | `/compliance/documents/stats`           | Dashboard stats            |
| 8  | `GET`    | `/compliance/documents/:id`             | Get single document        |
| 9  | `POST`   | `/compliance/documents`                 | Upload document            |
| 10 | `PATCH`  | `/compliance/documents/:id`             | Update document metadata   |
| 11 | `POST`   | `/compliance/documents/:id/replace`     | Replace document file      |
| 12 | `DELETE` | `/compliance/documents/:id`             | Delete document            |
| 13 | `GET`    | `/compliance/documents/:id/download`    | Download file              |
| 14 | `GET`    | `/compliance/documents/:id/view`        | View file inline           |
| 15 | `POST`   | `/compliance/documents/:id/scan`        | AI scan (extract + embed)  |
| 16 | `POST`   | `/compliance/documents/search`          | Semantic search            |
| 17 | `POST`   | `/compliance/documents/chat`            | AI chat assistant          |

All paths are prefixed with: `v1/api/organizations/:organizationId`
