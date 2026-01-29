export default () => ({
  recaptcha: {
    // Support both RECAPTCHA_SECRET_KEY and GOOGLE_RECAPTCHA_SECRET_KEY
    secretKey: process.env.RECAPTCHA_SECRET_KEY || process.env.GOOGLE_RECAPTCHA_SECRET_KEY || '',
    siteKey: process.env.RECAPTCHA_SITE_KEY || '',
    enabled: process.env.RECAPTCHA_ENABLED !== 'false', // Default to true if not explicitly false
    verifyUrl: 'https://www.google.com/recaptcha/api/siteverify',
  },
});

