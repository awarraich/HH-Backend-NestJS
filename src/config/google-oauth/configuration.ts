export default () => {
  console.log(process.env.GOOGLE_CALLBACK_URL);
  console.log(process.env.GOOGLE_CLIENT_ID);
  console.log(process.env.GOOGLE_CLIENT_SECRET);
  console.log(process.env.GOOGLE_OAUTH_ENABLED);
  console.log(process.env.NODE_ENV);
  console.log(process.env.HHBACKEND_URL);
  console.log(process.env.API_PREFIX);
  console.log(process.env.API_PREFIX);
  return {
    googleOAuth: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: 'http://127.0.0.1:8000/accounts/google/login/callback/', // process.env.GOOGLE_CALLBACK_URL || '',
      enabled: process.env.GOOGLE_OAUTH_ENABLED !== 'false', // Default to true if not explicitly false
    },
  };
};

