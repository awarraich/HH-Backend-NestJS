export type AgentLlmProvider = 'anthropic' | 'openai';

const resolveProvider = (): AgentLlmProvider => {
  const v = (process.env.GOOGLE_CHAT_AGENT_PROVIDER || '').toLowerCase();
  if (v === 'openai') return 'openai';
  return 'anthropic';
};

export default () => ({
  googleChatAgent: {
    enabled: process.env.GOOGLE_CHAT_AGENT_ENABLED === 'true',
    provider: resolveProvider(),
    // Anthropic models — used when provider='anthropic'.
    model: process.env.GOOGLE_CHAT_AGENT_MODEL || 'claude-sonnet-4-5-20250929',
    triageModel:
      process.env.GOOGLE_CHAT_AGENT_TRIAGE_MODEL ||
      'claude-haiku-4-5-20251001',
    // OpenAI models — used when provider='openai'.
    openaiModel: process.env.GOOGLE_CHAT_AGENT_OPENAI_MODEL || 'gpt-4o',
    openaiTriageModel:
      process.env.GOOGLE_CHAT_AGENT_OPENAI_TRIAGE_MODEL || 'gpt-4o-mini',
    maxTokens: parseInt(
      process.env.GOOGLE_CHAT_AGENT_MAX_TOKENS || '2048',
      10,
    ),
    turnTimeoutMs: parseInt(
      process.env.GOOGLE_CHAT_AGENT_TURN_TIMEOUT_MS || '30000',
      10,
    ),
    freeMessagesPerUser: parseInt(
      process.env.GOOGLE_CHAT_AGENT_FREE_MESSAGES_PER_USER || '50',
      10,
    ),
    // Off by default until compliance gate C8 is cleared (see plan §0).
    piiRedaction: process.env.GOOGLE_CHAT_AGENT_PII_REDACTION === 'true',
  },
});
