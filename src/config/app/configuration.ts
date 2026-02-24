export default () => ({
  app: {
    port: parseInt(process.env.PORT || '8000', 10),
    environment: process.env.NODE_ENV || 'development',
    api: {
      // Must be empty: controllers use full path (e.g. v1/api/blogs). If API_PREFIX is set to v1/api, GET /v1/api/blogs becomes 404 (route would be /v1/api/v1/api/blogs).
      prefix: process.env.API_PREFIX ?? '',
    },
    frontendUrl:
      process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '',
  },
  mcp: {
    port: parseInt(process.env.MCP_PORT || '8002', 10),
  },
});
