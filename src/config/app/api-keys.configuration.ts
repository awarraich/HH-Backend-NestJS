export default () => ({
  apiKeys: {
    openai: process.env.OPENAI_API_KEY || '',
    anthropic: process.env.ANTHROPIC_API_KEY || '',
  },
  llm: {
    provider: process.env.LLM_PROVIDER || 'openai',
    model: process.env.LLM_MODEL || 'gpt-4o-mini',
    openai: {
      model: process.env.OPENAI_REASONING_MODEL || 'gpt-4o',
    },
    bedrock: {
      region: process.env.AWS_REGION,
      modelId: process.env.LLM_BEDROCK_MODEL_ID,
    },
  },
  embedding: {
    provider: process.env.EMBEDDING_PROVIDER || 'openai',
    model: process.env.EMBEDDING_MODEL || 'text-embedding-3-small',
  },
});
