# Patient Chat API

All endpoints require `JwtAuthGuard` (Bearer token).

Base path: `v1/api/patient-chat`

## Conversations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/conversations` | List conversations. Query: `organizationId`, `patientId`, `limit`, `offset` |
| POST | `/conversations` | Create a new conversation (body: `CreateConversationDto`) |
| GET | `/conversations/:conversationId` | Get one conversation with all messages |

## Messages

| Method | Path | Description |
|--------|------|-------------|
| GET | `/conversations/:conversationId/messages` | List messages in a conversation |
| POST | `/conversations/:conversationId/messages` | Send a message (body: `{ "body": "..." }`) |

## Recipients (New message modal)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/recipients` | List message recipients. Query: `category` (organization, lab, doctor, clinical, therapist) |

## DTOs

- **CreateConversationDto**: `organizationId?`, `patientId?`, `recipientType`, `recipientEntityId?`, `recipientDisplayName`, `recipientRole?`, `subject?`
- **CreateMessageDto**: `body`
