export class OrganizationStaffCreatedEmailTemplate {
  static generate(
    userName: string,
    userEmail: string,
    temporaryPassword: string,
    loginUrl: string,
    expiresInHours: number = 24,
  ): {
    subject: string;
    html: string;
    text: string;
  } {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Welcome to homehealth.ai - Your Staff Account Has Been Created</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  
  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    Your staff account has been created on homehealth.ai. Use the credentials in this email to log in.
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
                      Welcome to homehealth.ai
                    </h1>
                    <p style="margin: 12px 0 0 0; color: #6b7280; font-size: 16px; line-height: 1.5;">
                      Your staff account has been created
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
                      Your staff account has been created on <strong style="color: #111827;">homehealth.ai</strong>. Below are your login credentials. You can log in immediately using the button below.
                    </p>
                  </td>
                </tr>
                
                <!-- Credentials Box -->
                <tr>
                  <td style="padding-bottom: 24px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background: linear-gradient(135deg, #f5f3ff 0%, #fef3c7 100%); border-radius: 16px; border: 2px solid #e9d5ff; overflow: hidden;">
                      <tr>
                        <td style="padding: 24px;">
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                            <tr>
                              <td style="padding-bottom: 16px;">
                                <p style="margin: 0 0 8px 0; color: #6b21a8; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">
                                  Email Address
                                </p>
                                <p style="margin: 0; color: #111827; font-size: 16px; font-weight: 600; font-family: 'Courier New', monospace;">
                                  ${userEmail}
                                </p>
                              </td>
                            </tr>
                            <tr>
                              <td>
                                <p style="margin: 0 0 8px 0; color: #6b21a8; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">
                                  Temporary Password
                                </p>
                                <p style="margin: 0; color: #111827; font-size: 16px; font-weight: 600; font-family: 'Courier New', monospace;">
                                  ${temporaryPassword}
                                </p>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Expiration Notice -->
                <tr>
                  <td style="padding-bottom: 24px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background: linear-gradient(135deg, #fef2f2 0%, #fff7ed 100%); border-radius: 16px; border: 2px solid #fee2e2; overflow: hidden;">
                      <tr>
                        <td style="padding: 24px;">
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                            <tr>
                              <td valign="top" style="width: 40px; padding-right: 16px;">
                                <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); border-radius: 10px; display: inline-block;">
                                  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" height="100%">
                                    <tr>
                                      <td align="center" valign="middle" style="color: #ffffff; font-size: 20px; font-weight: 700;">
                                        &#8986;
                                      </td>
                                    </tr>
                                  </table>
                                </div>
                              </td>
                              <td valign="top">
                                <p style="margin: 0 0 8px 0; color: #92400e; font-size: 15px; font-weight: 700; line-height: 1.4;">
                                  Temporary Password Notice
                                </p>
                                <p style="margin: 0; color: #b45309; font-size: 14px; line-height: 1.6;">
                                  This temporary password expires in <strong>${expiresInHours} hours</strong>. You must change it on your first login for security.
                                </p>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- CTA Button -->
                <tr>
                  <td align="center" style="padding-bottom: 36px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="border-radius: 14px; background: linear-gradient(135deg, #7c3aed 0%, #ec4899 100%); box-shadow: 0 8px 24px rgba(124, 58, 237, 0.35);">
                          <a href="${loginUrl}" target="_blank" style="display: inline-block; padding: 18px 56px; color: #ffffff; font-size: 17px; font-weight: 700; text-decoration: none; border-radius: 14px; letter-spacing: 0.3px;">
                            Log In to Your Account
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Security Notice Box -->
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
                                  Please keep your login credentials secure. We recommend changing your password after your first login for added security.
                                </p>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Login Link -->
                <tr>
                  <td style="padding-top: 32px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; border-radius: 12px; border: 1px solid #e5e7eb;">
                      <tr>
                        <td style="padding: 20px;">
                          <p style="margin: 0 0 12px 0; color: #111827; font-size: 14px; font-weight: 700; line-height: 1.5;">
                            Ready to log in?
                          </p>
                          <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                            You can log in at:
                          </p>
                          <div style="padding: 12px; background-color: #ffffff; border-radius: 8px; border: 1px solid #e5e7eb;">
                            <a href="${loginUrl}" style="color: #7c3aed; font-size: 14px; text-decoration: none; font-weight: 600; font-family: 'Courier New', monospace;">
                              ${loginUrl}
                            </a>
                          </div>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Help Text -->
                <tr>
                  <td style="padding-top: 32px;">
                    <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                      <strong style="color: #111827;">Need help?</strong><br>
                      If you have any questions or need assistance, please contact our support team at <a href="mailto:support@homehealth.ai" style="color: #7c3aed; text-decoration: none; font-weight: 600;">support@homehealth.ai</a>
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
    `.trim();

    const text = `
Welcome to homehealth.ai - Your Staff Account Has Been Created

Hello ${userName},

Your staff account has been created on homehealth.ai. Below are your login credentials:

Email Address: ${userEmail}
Temporary Password: ${temporaryPassword}

This temporary password expires in ${expiresInHours} hours. You must change it on your first login for security.

Log in at:
${loginUrl}

Security Notice:
Please keep your login credentials secure. We recommend changing your password after your first login for added security.

Need help?
If you have any questions or need assistance, please contact our support team at support@homehealth.ai

---
homehealth.ai
AI-Powered Healthcare Management Platform

© 2026 homehealth.ai. All rights reserved.
    `.trim();

    return {
      subject: 'Welcome to homehealth.ai - Your Staff Account Has Been Created',
      html,
      text,
    };
  }
}
