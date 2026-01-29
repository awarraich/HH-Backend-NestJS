export class PasswordResetEmailTemplate {
  static generate(
    passwordResetUrl: string,
    token: string,
    userName: string,
    userEmail: string,
  ): {
    subject: string;
    html: string;
    text: string;
  } {
    const fullUrl = `${passwordResetUrl}?token=${token}`;

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Reset Your Password - homehealth.ai</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  
  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    Reset your homehealth.ai password securely.
  </div>

  <!-- Wrapper Table -->
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 60px 20px;">
    <tr>
      <td align="center">
        <!-- Container Table -->
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08); overflow: hidden;">
          
          <!-- Decorative Top Border -->
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #ef4444 0%, #f97316 50%, #f59e0b 100%);"></td>
          </tr>

          <!-- Header with Logo -->
          <tr>
            <td style="padding: 50px 50px 40px 50px; text-align: center; background-color: #ffffff;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center">
                    <!-- Logo -->
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="padding: 0;">
                          <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #ef4444 0%, #f97316 100%); border-radius: 20px; display: inline-block; position: relative; box-shadow: 0 8px 20px rgba(239, 68, 68, 0.3);">
                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" height="100%">
                              <tr>
                                <td align="center" valign="middle" style="color: #ffffff; font-size: 36px; font-weight: 800; letter-spacing: -1px;">
                                  H+
                                </td>
                              </tr>
                            </table>
                          </div>
                        </td>
                      </tr>
                    </table>
                    
                    <h1 style="margin: 30px 0 0 0; color: #111827; font-size: 32px; font-weight: 800; line-height: 1.2; letter-spacing: -0.5px;">
                      Reset Your Password
                    </h1>
                    <p style="margin: 12px 0 0 0; color: #6b7280; font-size: 16px; line-height: 1.5;">
                      Secure password recovery
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Main Content -->
          <tr>
            <td style="padding: 0 50px 50px 50px;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <!-- Greeting -->
                <tr>
                  <td style="padding-bottom: 24px;">
                    <p style="margin: 0; color: #111827; font-size: 17px; line-height: 1.6;">
                      Hello <strong style="color: #ef4444;">${userName}</strong>,
                    </p>
                  </td>
                </tr>
                
                <!-- Body Text -->
                <tr>
                  <td style="padding-bottom: 20px;">
                    <p style="margin: 0; color: #4b5563; font-size: 16px; line-height: 1.7;">
                      We received a request to reset the password for your <strong style="color: #111827;">homehealth.ai</strong> account. If you made this request, click the button below to create a new password.
                    </p>
                  </td>
                </tr>
                
                <tr>
                  <td style="padding-bottom: 36px;">
                    <p style="margin: 0; color: #4b5563; font-size: 16px; line-height: 1.7;">
                      This password reset link will expire in <strong style="color: #111827;">1 hour</strong> for security purposes.
                    </p>
                  </td>
                </tr>
                
                <!-- CTA Button -->
                <tr>
                  <td align="center" style="padding-bottom: 36px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="border-radius: 14px; background: linear-gradient(135deg, #ef4444 0%, #f97316 100%); box-shadow: 0 8px 24px rgba(239, 68, 68, 0.35);">
                          <a href="${fullUrl}" target="_blank" style="display: inline-block; padding: 18px 56px; color: #ffffff; font-size: 17px; font-weight: 700; text-decoration: none; border-radius: 14px; letter-spacing: 0.3px;">
                            Reset Password
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Security Warning Box -->
                <tr>
                  <td>
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background: linear-gradient(135deg, #fef2f2 0%, #fff7ed 100%); border-radius: 16px; border: 2px solid #fee2e2; overflow: hidden;">
                      <tr>
                        <td style="padding: 24px;">
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                            <tr>
                              <td valign="top" style="width: 40px; padding-right: 16px;">
                                <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); border-radius: 10px; display: inline-block;">
                                  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" height="100%">
                                    <tr>
                                      <td align="center" valign="middle" style="color: #ffffff; font-size: 20px; font-weight: 700;">
                                        &#9888;
                                      </td>
                                    </tr>
                                  </table>
                                </div>
                              </td>
                              <td valign="top">
                                <p style="margin: 0 0 8px 0; color: #991b1b; font-size: 15px; font-weight: 700; line-height: 1.4;">
                                  Security Notice
                                </p>
                                <p style="margin: 0; color: #b91c1c; font-size: 14px; line-height: 1.6;">
                                  This link expires in 1 hour. Never share this link with anyone. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
                                </p>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Alternative Link Section -->
                <tr>
                  <td style="padding-top: 36px; border-top: 2px solid #f3f4f6; margin-top: 36px;">
                    <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 14px; line-height: 1.6; font-weight: 600;">
                      Button not working?
                    </p>
                    <p style="margin: 0 0 12px 0; color: #6b7280; font-size: 14px; line-height: 1.6;">
                      Copy and paste this link into your browser:
                    </p>
                    <div style="padding: 16px; background-color: #f9fafb; border-radius: 10px; border: 1px solid #e5e7eb; word-break: break-all;">
                      <a href="${fullUrl}" style="color: #ef4444; font-size: 13px; text-decoration: none; font-family: 'Courier New', monospace;">
                        ${fullUrl}
                      </a>
                    </div>
                  </td>
                </tr>
                
                <!-- Additional Security Info -->
                <tr>
                  <td style="padding-top: 32px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; border-radius: 12px; border: 1px solid #e5e7eb;">
                      <tr>
                        <td style="padding: 20px;">
                          <p style="margin: 0 0 12px 0; color: #111827; font-size: 14px; font-weight: 700; line-height: 1.5;">
                            Why am I receiving this?
                          </p>
                          <p style="margin: 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                            Someone (hopefully you) requested a password reset for the homehealth.ai account associated with <strong style="color: #111827;">${userEmail}</strong>. If this wasn't you, please contact our security team immediately.
                          </p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Help Text -->
                <tr>
                  <td style="padding-top: 32px;">
                    <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                      <strong style="color: #111827;">Didn't request this?</strong><br>
                      If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.
                    </p>
                    <p style="margin: 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                      Need help? Contact our support team at <a href="mailto:support@homehealth.ai" style="color: #ef4444; text-decoration: none; font-weight: 600;">support@homehealth.ai</a>
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="padding: 40px 50px; background: linear-gradient(180deg, #fafbfc 0%, #f3f4f6 100%); border-top: 2px solid #e5e7eb;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center" style="padding-bottom: 20px;">
                    <p style="margin: 0; color: #111827; font-size: 18px; font-weight: 800; letter-spacing: -0.3px;">
                      homehealth.ai
                    </p>
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding-bottom: 20px;">
                    <p style="margin: 0; color: #6b7280; font-size: 14px; line-height: 1.6;">
                      AI-Powered Healthcare Management Platform
                    </p>
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding-bottom: 24px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="padding: 0 12px;">
                          <a href="#" style="color: #ef4444; text-decoration: none; font-size: 14px; font-weight: 600;">Twitter</a>
                        </td>
                        <td style="color: #d1d5db; padding: 0 8px;">|</td>
                        <td style="padding: 0 12px;">
                          <a href="#" style="color: #ef4444; text-decoration: none; font-size: 14px; font-weight: 600;">LinkedIn</a>
                        </td>
                        <td style="color: #d1d5db; padding: 0 8px;">|</td>
                        <td style="padding: 0 12px;">
                          <a href="#" style="color: #ef4444; text-decoration: none; font-size: 14px; font-weight: 600;">Facebook</a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td align="center">
                    <p style="margin: 0; color: #9ca3af; font-size: 12px; line-height: 1.6;">
                      &copy; 2026 homehealth.ai. All rights reserved.
                    </p>
                    <p style="margin: 8px 0 0 0; color: #9ca3af; font-size: 12px; line-height: 1.6;">
                      <a href="#" style="color: #9ca3af; text-decoration: underline;">Privacy Policy</a> &bull; 
                      <a href="#" style="color: #9ca3af; text-decoration: underline;">Terms of Service</a> &bull; 
                      <a href="#" style="color: #9ca3af; text-decoration: underline;">Unsubscribe</a>
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `;

    const text = `
Reset Your Password - homehealth.ai

Hello ${userName},

We received a request to reset the password for your homehealth.ai account. If you made this request, click the link below to create a new password.

This password reset link will expire in 1 hour for security purposes.

Reset Password Link:
${fullUrl}

Security Notice:
This link expires in 1 hour. Never share this link with anyone. If you didn't request a password reset, please ignore this email and your password will remain unchanged.

Why am I receiving this?
Someone (hopefully you) requested a password reset for the homehealth.ai account associated with ${userEmail}. If this wasn't you, please contact our security team immediately.

Didn't request this?
If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.

Need help? Contact our support team at support@homehealth.ai

---
homehealth.ai
AI-Powered Healthcare Management Platform

© 2026 homehealth.ai. All rights reserved.
    `;

    return {
      subject: 'Reset Your Password - homehealth.ai',
      html: html.trim(),
      text: text.trim(),
    };
  }
}
