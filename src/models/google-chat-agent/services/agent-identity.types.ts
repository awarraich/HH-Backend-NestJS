/**
 * The trusted "who is asking" record for the Google Chat agent.
 * Produced by AgentIdentityService.resolve() and passed into every tool.
 *
 * IDs are uuid strings — they match the User / Organization PKs in this repo.
 */
export interface ResolvedAgentUser {
  userId: string;
  organizationId: string;
  timezone: string;
  chatUserId: string;
  chatSpaceName: string | null;
}

/**
 * Until User/Organization gain a real timezone column, the agent operates
 * in UTC. Region-agnostic on purpose — distinct from src/mcp/'s
 * FALLBACK_TIMEZONE (which we deliberately don't import).
 */
export const AGENT_DEFAULT_TIMEZONE = 'UTC';
