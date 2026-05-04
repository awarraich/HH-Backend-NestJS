export default () => {
  return {
    googleChat: {
      verifySignature: process.env.GOOGLE_CHAT_VERIFY_SIGNATURE !== 'false',
      audience: process.env.GOOGLE_CHAT_AUDIENCE || '',
      issuer: process.env.GOOGLE_CHAT_ISSUER || 'chat@system.gserviceaccount.com',
      serviceAccountJson: process.env.GOOGLE_CHAT_SERVICE_ACCOUNT_JSON || '',
      appId: process.env.GOOGLE_CHAT_APP_ID || '',
      adminInstallUrl: process.env.GOOGLE_CHAT_ADMIN_INSTALL_URL || '',
    },
  };
};
