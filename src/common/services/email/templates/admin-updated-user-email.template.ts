export class AdminUpdatedUserEmailTemplate {
  static generate(
    userName: string,
    userEmail: string,
    changes: {
      password?: boolean;
      temporaryPassword?: string;
      email?: { old: string; new: string };
      firstName?: { old: string; new: string };
      lastName?: { old: string; new: string };
      role?: { old: string; new: string };
    },
    loginUrl: string,
  ): {
    subject: string;
    html: string;
    text: string;
  } {
    const hasSensitiveChanges = changes.password || changes.email;

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Your Account Has Been Updated - homehealth.ai</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  
  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    Your homehealth.ai account has been updated by an administrator.
  </div>

  <!-- Wrapper Table -->
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 60px 20px;">
    <tr>
      <td align="center">
        <!-- Container Table -->
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.08); overflow: hidden;">
          
          <!-- Decorative Top Border -->
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #f59e0b 0%, #ef4444 50%, #dc2626 100%);"></td>
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
                          <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #f59e0b 0%, #ef4444 100%); border-radius: 20px; display: inline-block; position: relative; box-shadow: 0 8px 20px rgba(245, 158, 11, 0.3);">
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
                      Account Updated
                    </h1>
                    <p style="margin: 12px 0 0 0; color: #6b7280; font-size: 16px; line-height: 1.5;">
                      Important security notice
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
                      Hello <strong style="color: #f59e0b;">${userName}</strong>,
                    </p>
                  </td>
                </tr>
                
                <!-- Security Notice -->
                ${hasSensitiveChanges ? `
                <tr>
                  <td style="padding-bottom: 24px;">
                    <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px 20px; border-radius: 8px;">
                      <p style="margin: 0; color: #92400e; font-size: 15px; line-height: 1.6; font-weight: 600;">
                        Security Alert: Your account has been updated by an administrator. ${changes.password ? 'Your password has been changed and you have been logged out for security reasons.' : changes.email ? 'Your email address has been changed and you have been logged out for security reasons.' : 'You have been logged out for security reasons.'}
                      </p>
                    </div>
                  </td>
                </tr>
                ` : ''}
                
                <!-- Changes Summary -->
                <tr>
                  <td style="padding-bottom: 24px;">
                    <p style="margin: 0 0 16px 0; color: #111827; font-size: 16px; line-height: 1.6; font-weight: 600;">
                      The following changes were made to your account:
                    </p>
                    <div style="background-color: #f9fafb; border-radius: 12px; padding: 20px; border: 1px solid #e5e7eb;">
                      <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                        ${changes.password ? `
                        <tr>
                          <td style="padding-bottom: 12px;">
                            <div style="background-color: #fef2f2; border-left: 4px solid #dc2626; padding: 16px 20px; border-radius: 8px; margin-bottom: 12px;">
                              <p style="margin: 0 0 8px 0; color: #991b1b; font-size: 15px; line-height: 1.6; font-weight: 600;">
                                Password: Changed
                              </p>
                              ${changes.temporaryPassword ? `
                              <p style="margin: 0 0 8px 0; color: #991b1b; font-size: 14px; line-height: 1.6;">
                                <strong>Temporary Password:</strong> <code style="background-color: #fee2e2; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 14px; color: #991b1b;">${changes.temporaryPassword}</code>
                              </p>
                              <p style="margin: 0; color: #991b1b; font-size: 13px; line-height: 1.6;">
                                This temporary password expires in 24 hours. You must change it on your first login.
                              </p>
                              ` : ''}
                            </div>
                          </td>
                        </tr>
                        ` : ''}
                        ${changes.email ? `
                        <tr>
                          <td style="padding-bottom: 12px;">
                            <p style="margin: 0; color: #111827; font-size: 15px; line-height: 1.6;">
                              <strong style="color: #dc2626;">Email:</strong> ${changes.email.old} → ${changes.email.new}
                            </p>
                          </td>
                        </tr>
                        ` : ''}
                        ${changes.firstName ? `
                        <tr>
                          <td style="padding-bottom: 12px;">
                            <p style="margin: 0; color: #111827; font-size: 15px; line-height: 1.6;">
                              <strong>First Name:</strong> ${changes.firstName.old} → ${changes.firstName.new}
                            </p>
                          </td>
                        </tr>
                        ` : ''}
                        ${changes.lastName ? `
                        <tr>
                          <td style="padding-bottom: 12px;">
                            <p style="margin: 0; color: #111827; font-size: 15px; line-height: 1.6;">
                              <strong>Last Name:</strong> ${changes.lastName.old} → ${changes.lastName.new}
                            </p>
                          </td>
                        </tr>
                        ` : ''}
                        ${changes.role ? `
                        <tr>
                          <td style="padding-bottom: 12px;">
                            <p style="margin: 0; color: #111827; font-size: 15px; line-height: 1.6;">
                              <strong>Role:</strong> ${changes.role.old} → ${changes.role.new}
                            </p>
                          </td>
                        </tr>
                        ` : ''}
                      </table>
                    </div>
                  </td>
                </tr>
                
                ${hasSensitiveChanges ? `
                <!-- Action Required -->
                <tr>
                  <td style="padding-bottom: 24px;">
                    <p style="margin: 0 0 16px 0; color: #111827; font-size: 16px; line-height: 1.6; font-weight: 600;">
                      Action Required:
                    </p>
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.6;">
                      ${changes.password ? 'Please log in with your new password. ' : ''}${changes.email ? 'Please log in using your new email address. ' : ''}If you did not request these changes, please contact our support team immediately.
                    </p>
                  </td>
                </tr>
                
                <!-- Login Button -->
                <tr>
                  <td style="padding-bottom: 24px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                      <tr>
                        <td align="center" style="padding: 0;">
                          <div style="background: linear-gradient(135deg, #f59e0b 0%, #ef4444 100%); border-radius: 12px; padding: 2px; display: inline-block;">
                            <a href="${loginUrl}" style="display: inline-block; background-color: #ffffff; color: #dc2626; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-size: 16px; font-weight: 700; letter-spacing: -0.3px; text-align: center;">
                              Log In to Your Account
                            </a>
                          </div>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                ` : ''}
                
                <!-- Help Text -->
                <tr>
                  <td style="padding-top: 32px;">
                    <p style="margin: 0 0 16px 0; color: #6b7280; font-size: 14px; line-height: 1.7;">
                      <strong style="color: #111827;">Need help?</strong><br>
                      If you have any questions or did not request these changes, please contact our support team at <a href="mailto:support@homehealth.ai" style="color: #f59e0b; text-decoration: none; font-weight: 600;">support@homehealth.ai</a>
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
                  <td align="center">
                    <p style="margin: 0; color: #9ca3af; font-size: 12px; line-height: 1.6;">
                      &copy; 2026 homehealth.ai. All rights reserved.
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
Your Account Has Been Updated - homehealth.ai

Hello ${userName},

Your account on homehealth.ai has been updated by an administrator.

${hasSensitiveChanges ? `SECURITY ALERT: ${changes.password ? 'Your password has been changed and you have been logged out for security reasons. ' : changes.email ? 'Your email address has been changed and you have been logged out for security reasons. ' : 'You have been logged out for security reasons.'}` : ''}

The following changes were made to your account:

${changes.password ? `Password: Changed${changes.temporaryPassword ? `\nTemporary Password: ${changes.temporaryPassword}\n(This temporary password expires in 24 hours. You must change it on your first login.)` : ''}\n` : ''}${changes.email ? `Email: ${changes.email.old} → ${changes.email.new}\n` : ''}${changes.firstName ? `First Name: ${changes.firstName.old} → ${changes.firstName.new}\n` : ''}${changes.lastName ? `Last Name: ${changes.lastName.old} → ${changes.lastName.new}\n` : ''}${changes.role ? `Role: ${changes.role.old} → ${changes.role.new}\n` : ''}
${hasSensitiveChanges ? `Action Required:\n${changes.password && changes.temporaryPassword ? 'Please log in with your temporary password and change it immediately. ' : changes.password ? 'Please log in with your new password. ' : ''}${changes.email ? 'Please log in using your new email address. ' : ''}If you did not request these changes, please contact our support team immediately.\n\nLog in at: ${loginUrl}\n` : ''}
Need help?
If you have any questions or did not request these changes, please contact our support team at support@homehealth.ai

---
homehealth.ai
AI-Powered Healthcare Management Platform

© 2026 homehealth.ai. All rights reserved.
    `;

    return {
      subject: hasSensitiveChanges
        ? 'Security Alert: Your Account Has Been Updated - homehealth.ai'
        : 'Your Account Has Been Updated - homehealth.ai',
      html: html.trim(),
      text: text.trim(),
    };
  }
}
