export class VerificationEmailTemplate {
  static generate(
    verificationUrl: string,
    token: string,
    userName: string,
    userEmail: string,
  ): {
    subject: string;
    html: string;
    text: string;
  } {
    const fullUrl = `${verificationUrl}?token=${token}`;

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Verify Your Email - homehealth.ai</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  
  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    Complete your homehealth.ai registration by verifying your email address.
  </div>

  <!-- Wrapper Table -->
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 60px 20px;">
    <tr>
      <td align="center">
        <!-- Container Table -->
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08); overflow: hidden;">
          
          <!-- Decorative Top Border -->
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #7c3aed 0%, #ec4899 50%, #f97316 100%);"></td>
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
                          <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #7c3aed 0%, #ec4899 100%); border-radius: 20px; display: inline-block; position: relative; box-shadow: 0 8px 20px rgba(124, 58, 237, 0.3);">
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
                      Verify Your Email
                    </h1>
                    <p style="margin: 12px 0 0 0; color: #6b7280; font-size: 16px; line-height: 1.5;">
                      Welcome to homehealth.ai
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
                      Hello <strong style="color: #7c3aed;">${userName}</strong>,
                    </p>
                  </td>
                </tr>
                
                <!-- Body Text -->
                <tr>
                  <td style="padding-bottom: 20px;">
                    <p style="margin: 0; color: #4b5563; font-size: 16px; line-height: 1.7;">
                      Thank you for creating an account with <strong style="color: #111827;">homehealth.ai</strong>. We're excited to have you join our AI-powered healthcare management platform.
                    </p>
                  </td>
                </tr>
                
                <tr>
                  <td style="padding-bottom: 36px;">
                    <p style="margin: 0; color: #4b5563; font-size: 16px; line-height: 1.7;">
                      To get started and access all features, please verify your email address by clicking the button below:
                    </p>
                  </td>
                </tr>
                
                <!-- CTA Button -->
                <tr>
                  <td align="center" style="padding-bottom: 36px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="border-radius: 14px; background: linear-gradient(135deg, #7c3aed 0%, #ec4899 100%); box-shadow: 0 8px 24px rgba(124, 58, 237, 0.35);">
                          <a href="${fullUrl}" target="_blank" style="display: inline-block; padding: 18px 56px; color: #ffffff; font-size: 17px; font-weight: 700; text-decoration: none; border-radius: 14px; letter-spacing: 0.3px;">
                            Verify Email Address
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Info Box with Icon -->
                <tr>
                  <td>
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background: linear-gradient(135deg, #eff6ff 0%, #f3e8ff 100%); border-radius: 16px; border: 2px solid #e0e7ff; overflow: hidden;">
                      <tr>
                        <td style="padding: 24px;">
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                            <tr>
                              <td valign="top" style="width: 40px; padding-right: 16px;">
                                <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #7c3aed 0%, #6366f1 100%); border-radius: 10px; display: inline-block;">
                                  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" height="100%">
                                    <tr>
                                      <td align="center" valign="middle" style="color: #ffffff; font-size: 20px; font-weight: 700;">
                                        &#8505;
                                      </td>
                                    </tr>
                                  </table>
                                </div>
                              </td>
                              <td valign="top">
                                <p style="margin: 0 0 8px 0; color: #4338ca; font-size: 15px; font-weight: 700; line-height: 1.4;">
                                  This link expires in 24 hours
                                </p>
                                <p style="margin: 0; color: #4c51bf; font-size: 14px; line-height: 1.6;">
                                  For security reasons, this verification link will expire in 24 hours. If it expires, you can request a new verification link from the login page.
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
                      <a href="${fullUrl}" style="color: #7c3aed; font-size: 13px; text-decoration: none; font-family: 'Courier New', monospace;">
                        ${fullUrl}
                      </a>
                    </div>
                  </td>
                </tr>
                
                <!-- Help Text -->
                <tr>
                  <td style="padding-top: 32px;">
                    <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                      <strong style="color: #111827;">Didn't create an account?</strong><br>
                      If you didn't sign up for homehealth.ai, you can safely ignore this email. No account will be created.
                    </p>
                    <p style="margin: 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                      Need help? Contact our support team at <a href="mailto:support@homehealth.ai" style="color: #7c3aed; text-decoration: none; font-weight: 600;">support@homehealth.ai</a>
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
                          <a href="#" style="color: #7c3aed; text-decoration: none; font-size: 14px; font-weight: 600;">Twitter</a>
                        </td>
                        <td style="color: #d1d5db; padding: 0 8px;">|</td>
                        <td style="padding: 0 12px;">
                          <a href="#" style="color: #7c3aed; text-decoration: none; font-size: 14px; font-weight: 600;">LinkedIn</a>
                        </td>
                        <td style="color: #d1d5db; padding: 0 8px;">|</td>
                        <td style="padding: 0 12px;">
                          <a href="#" style="color: #7c3aed; text-decoration: none; font-size: 14px; font-weight: 600;">Facebook</a>
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
Verify Your Email - homehealth.ai

Hello ${userName},

Thank you for creating an account with homehealth.ai. We're excited to have you join our AI-powered healthcare management platform.

To get started and access all features, please verify your email address by clicking the link below:

Verification Link:
${fullUrl}

This link expires in 24 hours. For security reasons, this verification link will expire in 24 hours. If it expires, you can request a new verification link from the login page.

Didn't create an account?
If you didn't sign up for homehealth.ai, you can safely ignore this email. No account will be created.

Need help? Contact our support team at support@homehealth.ai

---
homehealth.ai
AI-Powered Healthcare Management Platform

© 2026 homehealth.ai. All rights reserved.
    `;

    return {
      subject: 'Verify Your Email - homehealth.ai',
      html: html.trim(),
      text: text.trim(),
    };
  }
}
