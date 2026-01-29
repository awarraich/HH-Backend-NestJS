export default () => {
  const isProduction = process.env.NODE_ENV === 'production';
  const backendUrl = process.env.HHBACKEND_URL || '';
  const apiPrefix = process.env.API_PREFIX || 'v1/api';
  
  let callbackURL = process.env.GOOGLE_CALLBACK_URL;
  if (!callbackURL) {
    if (isProduction) {
      callbackURL = backendUrl 
        ? `${backendUrl}/${apiPrefix}/auth/accounts/google/login/callback`
        : '';
    } else {
      // Development: use GOOGLE_CALLBACK_URL_DEV or construct from HHBACKEND_URL
      callbackURL = process.env.GOOGLE_CALLBACK_URL_DEV || 
        (backendUrl ? `${backendUrl}/${apiPrefix}/auth/accounts/google/login/callback` : '');
    }
  }

  return {
    googleOAuth: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL,
      enabled: process.env.GOOGLE_OAUTH_ENABLED !== 'false', // Default to true if not explicitly false
    },
  };
};

