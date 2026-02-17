export default () => {
  return {
    googleOAuth: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: process.env.GOOGLE_CALLBACK_URL || '',
      enabled: process.env.GOOGLE_OAUTH_ENABLED !== 'false', // Default to true if not explicitly false
    },
  };
};

