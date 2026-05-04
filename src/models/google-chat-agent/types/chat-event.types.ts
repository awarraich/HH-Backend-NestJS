/**
 * Subset of the Google Chat event payload the agent reads. Distinct from
 * the notification module's `GoogleChatEventPayload` (which is intentionally
 * narrow for ADDED/REMOVED handling) — this one includes the message body
 * and thread context that MESSAGE events carry.
 *
 * Reference: https://developers.google.com/chat/api/reference/rest/v1/Event
 */
export interface AgentChatEvent {
  type?: string;
  user?: {
    name?: string;
    displayName?: string;
    email?: string;
  };
  space?: {
    name?: string;
  };
  message?: {
    text?: string;
    argumentText?: string;
    thread?: {
      name?: string;
    };
    attachment?: unknown[];
  };
}

/** Reply shape: either Card v2 or plain text. The webhook returns one of these directly. */
export type AgentReply =
  | { text: string }
  | import('../rendering/card.types').CardV2Message;
