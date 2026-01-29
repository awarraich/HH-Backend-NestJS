export default () => {
  const frontendUrl = process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '';
  
  return {
    email: {
      // Support both EMAIL_HOST and SMTP_HOST
      host: process.env.EMAIL_HOST || process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT || process.env.SMTP_PORT || '587', 10),
      secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
      auth: {
        // Support both EMAIL_USER and SMTP_USER, EMAIL_HOST_USER
        user: process.env.EMAIL_USER || process.env.SMTP_USER || process.env.EMAIL_HOST_USER || '',
        // Support both EMAIL_PASSWORD and SMTP_PASSWORD, EMAIL_HOST_PASSWORD
        pass: process.env.EMAIL_PASSWORD || process.env.SMTP_PASSWORD || process.env.EMAIL_HOST_PASSWORD || '',
      },
      // Support both EMAIL_FROM and FROM_EMAIL
      from: process.env.EMAIL_FROM || process.env.FROM_EMAIL || 'noreply@example.com',
      // Support both EMAIL_FROM_NAME and FROM_NAME
      fromName: process.env.EMAIL_FROM_NAME || process.env.FROM_NAME || 'Health Hub',
      verificationUrl: process.env.EMAIL_VERIFICATION_URL || 
        (process.env.HHBACKEND_URL 
          ? `${process.env.HHBACKEND_URL}/v1/api/auth/verify-email`
          : (frontendUrl ? `${frontendUrl}/verify-email` : '')),
      passwordResetUrl: process.env.EMAIL_PASSWORD_RESET_URL || (frontendUrl ? `${frontendUrl}/reset-password` : ''),
      // MailerSend configuration (optional)
      mailersend: {
        apiKey: process.env.MAILERSEND_API_KEY || '',
        fromEmail: process.env.MAILERSEND_FROM_EMAIL || '',
        fromName: process.env.MAILERSEND_FROM_NAME || '',
      },
      // SendGrid configuration (optional)
      sendgrid: {
        apiKey: process.env.SENDGRID_API_KEY || '',
      },
      supportEmail: process.env.SUPPORT_EMAIL || 'support@homehealth.ai',
    },
  };
};
