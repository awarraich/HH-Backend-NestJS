export default () => ({
  app: {
    port: parseInt(process.env.PORT || '3000', 10),
    environment: process.env.NODE_ENV || 'development',
    api: {
      prefix: process.env.API_PREFIX || 'v1/api',
    },
    frontendUrl:
      process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '',
  },
});
