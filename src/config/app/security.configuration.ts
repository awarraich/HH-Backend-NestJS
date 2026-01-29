export default () => ({
  security: {
    secretKey: process.env.SECURITY_SECRET_KEY || '',
  },
});

