export interface HireWelcomeOptions {
  applicantName: string;
  jobTitle: string;
  startDate?: string;
  employmentType?: string;
  organizationName?: string;
}

/**
 * Welcome email fired when HR presses the "Hire as Employee" button on an
 * accepted offer. The candidate becomes a real Employee in the target
 * organization and needs to be pointed at the employee workspace.
 */
export class HireWelcomeEmailTemplate {
  static generate(opts: HireWelcomeOptions): {
    subject: string;
    html: string;
    text: string;
  } {
    const {
      applicantName,
      jobTitle,
      startDate,
      employmentType,
      organizationName,
    } = opts;

    const brandName = organizationName?.trim() || 'homehealth.ai';
    const logoAlt = escapeHtml(brandName);

    const subject = organizationName
      ? `Welcome to ${organizationName} — ${jobTitle}`
      : `Welcome aboard — ${jobTitle}`;

    const logoBlock = `
                    <!--[if mso]>
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin-bottom:20px;">
                      <tr>
                        <td width="64" height="64" style="background:#059669;border-radius:14px;text-align:center;vertical-align:middle;font-family:Arial,sans-serif;font-size:28px;font-weight:700;color:#ffffff;">
                          H
                        </td>
                      </tr>
                    </table>
                    <![endif]-->
                    <!--[if !mso]><!-->
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 0 auto 20px auto;">
                      <tr>
                        <td width="64" height="64"
                            style="width:64px;height:64px;background:linear-gradient(135deg,#10b981 0%,#059669 100%);border-radius:14px;text-align:center;vertical-align:middle;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:28px;font-weight:700;color:#ffffff;line-height:64px;">
                          <img src="cid:logo@homehealth.ai" alt="${logoAlt}" width="64" height="64"
                               style="display:block;width:64px;height:64px;border-radius:14px;object-fit:cover;"
                               onerror="this.style.display='none'" />
                        </td>
                      </tr>
                    </table>
                    <!--<![endif]-->`;

    const detailsRows: string[] = [];
    if (jobTitle)
      detailsRows.push(tableRow('Position', escapeHtml(jobTitle), '#e5e7eb'));
    if (employmentType)
      detailsRows.push(
        tableRow('Employment Type', escapeHtml(formatEmpType(employmentType)), '#e5e7eb'),
      );
    if (startDate)
      detailsRows.push(tableRow('Start Date', escapeHtml(startDate), '#e5e7eb'));
    if (organizationName)
      detailsRows.push(
        tableRow('Organization', escapeHtml(organizationName), '#e5e7eb'),
      );

    const detailsBlock = detailsRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Your Role', '#059669', detailsRows.join(''))}</td></tr>`
      : '';

    const nextStepsBlock = `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('Next Steps', '#0ea5e9', nextStepsRows())}
                  </td>
                </tr>`;

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Welcome to ${escapeHtml(brandName)}</title>
  <style>
    @media only screen and (max-width: 600px) {
      .email-container { width: 100% !important; }
      .email-pad { padding: 24px !important; }
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <div style="display: none; max-height: 0; overflow: hidden;">
    Welcome to ${escapeHtml(brandName)}${jobTitle ? ` — your ${escapeHtml(jobTitle)} role starts now.` : ''}
  </div>
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 60px 20px;">
    <tr>
      <td align="center">
        <table role="presentation" class="email-container" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; width: 100%; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #10b981 0%, #059669 50%, #0ea5e9 100%);"></td>
          </tr>
          <tr>
            <td class="email-pad" style="padding: 40px 48px 28px 48px; text-align: center; background-color: #ffffff; border-bottom: 1px solid #f1f5f9;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center">
                    ${logoBlock}
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 0 auto 14px auto;">
                      <tr>
                        <td style="background: linear-gradient(135deg, #ecfdf5, #d1fae5); border: 1px solid #a7f3d0; border-radius: 24px; padding: 5px 16px;">
                          <span style="font-size: 11px; font-weight: 700; color: #059669; letter-spacing: 1px;">WELCOME ABOARD</span>
                        </td>
                      </tr>
                    </table>
                    <h1 style="margin: 0; color: #0f172a; font-size: 24px; font-weight: 700; line-height: 1.3; letter-spacing: -0.3px;">
                      You&rsquo;re officially part of the team!
                    </h1>
                    ${organizationName ? `<p style="margin: 6px 0 0 0; color: #64748b; font-size: 14px; line-height: 1.5;">${escapeHtml(organizationName)}</p>` : ''}
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td class="email-pad" style="padding: 32px 48px 40px 48px; background-color: #fafbfc;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td style="padding-bottom: 12px;">
                    <p style="margin: 0; color: #0f172a; font-size: 16px; line-height: 1.6;">
                      Dear ${escapeHtml(applicantName)},
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="padding-bottom: 28px;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.7;">
                      Congratulations &mdash; your offer has been finalized and you are now an employee
                      ${organizationName ? `of <strong style="color:#0f172a;">${escapeHtml(organizationName)}</strong>` : ''}.
                      We&rsquo;re delighted to have you on the team${jobTitle ? ` as our <strong style="color:#0f172a;">${escapeHtml(jobTitle)}</strong>` : ''}.
                    </p>
                  </td>
                </tr>
                ${detailsBlock}
                ${nextStepsBlock}
                <tr>
                  <td style="padding-top: 8px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 16px 0 0 0; color: #64748b; font-size: 13px; line-height: 1.6;">
                      Log in to your account to access the employee workspace, view your onboarding checklist, and find the people who&rsquo;ll help you get set up.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 48px; background: #ffffff; border-top: 1px solid #e5e7eb;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center">
                    <p style="margin: 0 0 4px 0; color: #0f172a; font-size: 13px; font-weight: 600; letter-spacing: -0.1px;">
                      ${escapeHtml(brandName)}
                    </p>
                    <p style="margin: 0 0 10px 0; color: #94a3b8; font-size: 12px;">
                      AI-Powered Healthcare Management Platform
                    </p>
                    <p style="margin: 0; color: #94a3b8; font-size: 11px;">
                      &copy; 2026 ${escapeHtml(brandName)}
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
</html>`.trim();

    const textLines: string[] = [
      subject,
      '',
      `Dear ${applicantName},`,
      '',
      `Congratulations — your offer has been finalized and you are now an employee${organizationName ? ` of ${organizationName}` : ''}.`,
      '',
      'YOUR ROLE',
    ];
    if (jobTitle) textLines.push(`  Position: ${jobTitle}`);
    if (employmentType)
      textLines.push(`  Employment Type: ${formatEmpType(employmentType)}`);
    if (startDate) textLines.push(`  Start Date: ${startDate}`);
    if (organizationName) textLines.push(`  Organization: ${organizationName}`);
    textLines.push(
      '',
      'NEXT STEPS',
      '  1. Log in to your account and switch to the employee workspace',
      '  2. Complete any onboarding documents assigned to you',
      '  3. Reach out to HR with any questions about your first day',
      '',
      '---',
      brandName,
      'AI-Powered Healthcare Management Platform',
      `© 2026 ${brandName}. All rights reserved.`,
    );

    return { subject, html, text: textLines.join('\n') };
  }
}

function tableRow(label: string, value: string, borderColor: string): string {
  return `
                  <tr>
                    <td style="padding: 8px 0; color: #6b7280; font-size: 14px; width: 45%; border-top: 1px solid ${borderColor};">
                      ${label}
                    </td>
                    <td style="padding: 8px 0; color: #111827; font-size: 14px; font-weight: 600; border-top: 1px solid ${borderColor};">
                      ${value}
                    </td>
                  </tr>`;
}

function sectionCard(title: string, accentColor: string, content: string): string {
  return `
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#ffffff;border:1px solid #e5e7eb;border-left:3px solid ${accentColor};border-radius:6px;">
      <tr>
        <td style="padding: 20px 24px;">
          <p style="margin: 0 0 4px 0; font-size: 11px; font-weight: 700; color: ${accentColor}; letter-spacing: 0.8px; text-transform: uppercase;">${title}</p>
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin-top: 8px;">
            ${content}
          </table>
        </td>
      </tr>
    </table>`;
}

function nextStepsRows(): string {
  const steps = [
    'Sign in to your account and switch to the employee workspace',
    'Complete any onboarding documents assigned to you',
    'Reach out to HR with any questions about your first day',
  ];
  return steps
    .map(
      (step, i) => `
                  <tr>
                    <td style="padding: 4px 0; vertical-align: top;">
                      <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                        <tr>
                          <td valign="top" style="width: 18px; padding-right: 10px; color: #0ea5e9; font-size: 13px; font-weight: 700; line-height: 1.6;">${i + 1}.</td>
                          <td style="color: #374151; font-size: 13px; line-height: 1.6;">${step}</td>
                        </tr>
                      </table>
                    </td>
                  </tr>`,
    )
    .join('');
}

function formatEmpType(s: string): string {
  const v = s.trim().toLowerCase().replace(/[_-]+/g, ' ');
  return v.charAt(0).toUpperCase() + v.slice(1);
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
