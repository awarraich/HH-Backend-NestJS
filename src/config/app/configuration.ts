export default () => ({
  app: {
    port: parseInt(process.env.PORT || '3000', 10),
    environment: process.env.NODE_ENV || 'development',
    api: {
      // Empty by default: controllers use full paths (v1/api/...). Set API_PREFIX only if you need an extra prefix (e.g. behind a proxy that strips it).
      prefix: process.env.API_PREFIX ?? '',
    },
    frontendUrl:
      process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '',
  },
});
