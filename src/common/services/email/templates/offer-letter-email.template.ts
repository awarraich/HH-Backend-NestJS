export interface OfferLetterOptions {
  applicantName: string;
  jobTitle: string;
  salary: string;
  startDate: string;
  offerContent: string;
  attachmentUrl?: string;
  benefits?: string;
  responseDeadline?: string;
  /** "full_time" | "part_time" | "contract" | "temporary" | "internship" */
  employmentType?: string;
  message?: string;
  jobLocation?: string;
  jobDescription?: string;
  organizationName?: string;
  contactName?: string;
  contactEmail?: string;
  contactPhone?: string;
}

export class OfferLetterEmailTemplate {
  static generate(opts: OfferLetterOptions): {
    subject: string;
    html: string;
    text: string;
  } {
    const {
      applicantName,
      jobTitle,
      salary,
      startDate,
      offerContent,
      attachmentUrl,
      benefits,
      responseDeadline,
      employmentType,
      message,
      jobLocation,
      jobDescription,
      organizationName,
      contactName,
      contactEmail,
      contactPhone,
    } = opts;

    const subject = organizationName
      ? `Offer of Employment – ${jobTitle} at ${organizationName}`
      : `Offer of Employment – ${jobTitle}`;

    const employmentLabel = formatEmploymentType(employmentType);
    const orgLine = organizationName
      ? `at <strong style="color:#0f172a;">${escapeHtml(organizationName)}</strong>`
      : '';
    const hrEmail = contactEmail ? escapeHtml(contactEmail) : 'hr@homehealth.ai';

    // ── Logo block — gradient square with image overlay ──────────────────────
    const logoBlock = `
                    <!--[if mso]>
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin-bottom:20px;">
                      <tr>
                        <td width="64" height="64" style="background:#7c3aed;border-radius:14px;text-align:center;vertical-align:middle;font-family:Arial,sans-serif;font-size:28px;font-weight:700;color:#ffffff;">
                          H
                        </td>
                      </tr>
                    </table>
                    <![endif]-->
                    <!--[if !mso]><!-->
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 0 auto 20px auto;">
                      <tr>
                        <td width="64" height="64"
                            style="width:64px;height:64px;background:linear-gradient(135deg,#7c3aed 0%,#ec4899 100%);border-radius:14px;text-align:center;vertical-align:middle;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;font-size:28px;font-weight:700;color:#ffffff;line-height:64px;">
                          <img src="cid:logo@homehealth.ai" alt="H" width="64" height="64"
                               style="display:block;width:64px;height:64px;border-radius:14px;"
                               onerror="this.style.display='none'" />
                        </td>
                      </tr>
                    </table>
                    <!--<![endif]-->`;

    // ── Role rows ────────────────────────────────────────────────────────────
    const roleRows: string[] = [];
    if (jobTitle)        roleRows.push(tableRow('Position',        escapeHtml(jobTitle),        '#e5e7eb'));
    if (employmentLabel) roleRows.push(tableRow('Employment Type', escapeHtml(employmentLabel), '#e5e7eb'));
    if (jobLocation)     roleRows.push(tableRow('Location',        escapeHtml(jobLocation),     '#e5e7eb'));

    const roleBlock = roleRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Role', '#4f46e5', roleRows.join(''))}</td></tr>`
      : '';

    // ── Start date rows ──────────────────────────────────────────────────────
    const startRows: string[] = [];
    if (startDate)        startRows.push(tableRow('Start Date',  escapeHtml(startDate),        '#e5e7eb'));
    if (responseDeadline) startRows.push(tableRow('Respond By',  escapeHtml(responseDeadline), '#e5e7eb'));

    const startBlock = startRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Key Dates', '#0891b2', startRows.join(''))}</td></tr>`
      : '';

    // ── Salary rows ──────────────────────────────────────────────────────────
    const salaryRows: string[] = [];
    if (salary) salaryRows.push(tableRow('Annual Salary',     escapeHtml(salary),            '#e5e7eb'));
    salaryRows.push(        tableRow('Payment Schedule', 'Monthly (last working day)',        '#e5e7eb'));
    salaryRows.push(        tableRow('Probation Period',  '3 months',                         '#e5e7eb'));

    const salaryBlock = salary
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Compensation', '#059669', salaryRows.join(''))}</td></tr>`
      : '';

    // ── Benefits block ───────────────────────────────────────────────────────
    const benefitsBlock = benefits?.trim()
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Benefits', '#7c3aed', benefitsTiles(benefits))}</td></tr>`
      : '';

    // ── Job description block ────────────────────────────────────────────────
    const descriptionBlock = jobDescription?.trim()
      ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('About the Role', '#475569', `<tr><td style="color:#374151;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(truncate(jobDescription, 600))}</td></tr>`)}
                  </td>
                </tr>`
      : '';

    // ── Offer content block ──────────────────────────────────────────────────
    const contentBlock = offerContent?.trim()
      ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('Offer Letter', '#0f172a', `<tr><td style="color:#374151;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(offerContent).replace(/\n/g, '<br>')}</td></tr>`)}
                  </td>
                </tr>`
      : '';

    // ── Team message block ───────────────────────────────────────────────────
    const messageBlock = message?.trim()
      ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#f9fafb;border-left:3px solid #94a3b8;border-radius:4px;">
                      <tr>
                        <td style="padding: 18px 24px;">
                          <p style="margin: 0 0 6px 0; font-size: 11px; font-weight: 700; color: #475569; letter-spacing: 0.8px; text-transform: uppercase;">A Note from the Team</p>
                          <p style="margin: 0; color: #374151; font-size: 14px; line-height: 1.7; white-space: pre-wrap;">${escapeHtml(message)}</p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>`
      : '';

    // ── Attachment CTA ───────────────────────────────────────────────────────
    const attachmentBlock = attachmentUrl
      ? `
                <tr>
                  <td align="center" style="padding: 16px 0 32px 0;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="border-radius: 6px; background: #0f172a;">
                          <a href="${escapeHtml(attachmentUrl)}" target="_blank" style="display: inline-block; padding: 14px 36px; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 6px; letter-spacing: 0.2px;">
                            Download Offer Letter (PDF)
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>`
      : '';

    // ── Contact block ────────────────────────────────────────────────────────
    const contactBlock =
      contactName || contactEmail || contactPhone
        ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#ffffff;border:1px solid #e5e7eb;border-radius:6px;">
                      <tr>
                        <td style="padding: 20px 24px;">
                          <p style="margin: 0 0 10px 0; color: #475569; font-size: 11px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase;">Point of Contact</p>
                          ${contactName  ? `<p style="margin: 0 0 4px; font-size: 15px; font-weight: 600; color: #0f172a;">${escapeHtml(contactName)}</p>` : ''}
                          ${contactEmail ? `<p style="margin: 0 0 2px; font-size: 13px;"><a href="mailto:${escapeHtml(contactEmail)}" style="color: #4f46e5; text-decoration: none;">${escapeHtml(contactEmail)}</a></p>` : ''}
                          ${contactPhone ? `<p style="margin: 0; font-size: 13px; color: #6b7280;">${escapeHtml(contactPhone)}</p>` : ''}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>`
        : '';

    // ── Candidate acceptance block ───────────────────────────────────────────
    const acceptanceBlock = `
                <tr>
                  <td style="padding: 16px 0 24px 0;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#ffffff;border:1px solid #e5e7eb;border-radius:6px;">
                      <tr>
                        <td style="padding: 24px;">
                          <p style="font-size: 11px; font-weight: 700; color: #475569; margin: 0 0 12px 0; letter-spacing: 0.8px; text-transform: uppercase;">Candidate Acceptance</p>
                          <p style="font-size: 13px; color: #4b5563; margin: 0 0 24px 0; line-height: 1.7;">
                            By signing below, I, <strong style="color:#0f172a;">${escapeHtml(applicantName)}</strong>, confirm that I have read and understood the terms of this offer and hereby accept the position of <strong style="color:#0f172a;">${escapeHtml(jobTitle)}</strong>${organizationName ? ` at <strong style="color:#0f172a;">${escapeHtml(organizationName)}</strong>` : ''}.
                          </p>
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                            <tr>
                              <td style="width:48%;padding-bottom:16px;vertical-align:bottom;">
                                <div style="border-bottom:1px solid #cbd5e1;height:36px;margin-bottom:6px;"></div>
                                <span style="font-size:11px;color:#64748b;letter-spacing:0.3px;">Candidate Signature</span>
                              </td>
                              <td style="width:4%;"></td>
                              <td style="width:48%;padding-bottom:16px;vertical-align:bottom;">
                                <div style="border-bottom:1px solid #cbd5e1;height:36px;margin-bottom:6px;"></div>
                                <span style="font-size:11px;color:#64748b;letter-spacing:0.3px;">Date</span>
                              </td>
                            </tr>
                            <tr>
                              <td style="vertical-align:bottom;">
                                <div style="border-bottom:1px solid #cbd5e1;height:36px;margin-bottom:6px;"></div>
                                <span style="font-size:11px;color:#64748b;letter-spacing:0.3px;">Printed Name</span>
                              </td>
                              <td></td>
                              <td style="vertical-align:bottom;">
                                <div style="border-bottom:1px solid #cbd5e1;height:36px;margin-bottom:6px;"></div>
                                <span style="font-size:11px;color:#64748b;letter-spacing:0.3px;">Personal Email</span>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>`;

    // ── HR signature block ───────────────────────────────────────────────────
    const hrSignatureBlock = `
                <tr>
                  <td style="padding-top: 24px; border-top: 1px solid #e5e7eb;">
                    <p style="font-size:11px;font-weight:700;color:#475569;margin:0 0 6px 0;letter-spacing:0.8px;text-transform:uppercase;">
                      Authorized by ${organizationName ? escapeHtml(organizationName) : 'homehealth.ai'}
                    </p>
                    <div style="border-bottom:1px solid #cbd5e1;width:180px;margin:16px 0 8px;"></div>
                    ${contactName ? `<p style="font-size:14px;font-weight:600;color:#0f172a;margin:0 0 2px;">${escapeHtml(contactName)}</p>` : ''}
                    <p style="font-size:13px;color:#64748b;margin:0 0 2px;">Head of Human Resources</p>
                    <p style="font-size:13px;margin:0;"><a href="mailto:${hrEmail}" style="color:#4f46e5;text-decoration:none;">${hrEmail}</a></p>
                  </td>
                </tr>`;

    // ── Full HTML ────────────────────────────────────────────────────────────
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Offer Letter – ${escapeHtml(jobTitle)} – homehealth.ai</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">

  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    Congratulations! You have received an offer for ${escapeHtml(jobTitle)}${organizationName ? ` at ${escapeHtml(organizationName)}` : ''} from homehealth.ai.
  </div>

  <!-- Wrapper Table -->
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 60px 20px;">
    <tr>
      <td align="center">

        <!-- Container Table -->
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; width: 100%; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">

          <!-- Top accent bar -->
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #7c3aed 0%, #ec4899 50%, #f97316 100%);"></td>
          </tr>

          <!-- Header -->
          <tr>
            <td style="padding: 40px 48px 28px 48px; text-align: center; background-color: #ffffff; border-bottom: 1px solid #f1f5f9;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center">

                    ${logoBlock}

                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 0 auto 14px auto;">
                      <tr>
                        <td style="background: linear-gradient(135deg, #eff6ff, #f3e8ff); border: 1px solid #e0e7ff; border-radius: 24px; padding: 5px 16px;">
                          <span style="font-size: 11px; font-weight: 700; color: #7c3aed; letter-spacing: 1px;">OFFER OF EMPLOYMENT</span>
                        </td>
                      </tr>
                    </table>

                    <h1 style="margin: 0; color: #0f172a; font-size: 24px; font-weight: 700; line-height: 1.3; letter-spacing: -0.3px;">
                      ${escapeHtml(jobTitle)}
                    </h1>
                    ${organizationName ? `<p style="margin: 6px 0 0 0; color: #64748b; font-size: 14px; line-height: 1.5;">${escapeHtml(organizationName)}</p>` : ''}

                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content -->
          <tr>
            <td style="padding: 32px 48px 40px 48px; background-color: #fafbfc;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">

                <!-- Greeting -->
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
                      Following our review of your application and interview, we are pleased to extend an offer for the position of
                      <strong style="color: #0f172a;">${escapeHtml(jobTitle)}</strong> ${orgLine}.
                      The complete terms of this offer are outlined below for your consideration.
                    </p>
                  </td>
                </tr>

                ${roleBlock}
                ${startBlock}
                ${salaryBlock}
                ${benefitsBlock}
                ${descriptionBlock}
                ${contentBlock}
                ${messageBlock}
                ${attachmentBlock}
                ${contactBlock}

                <!-- Closing -->
                <tr>
                  <td style="padding: 8px 0 24px 0;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.7;">
                      Please review the terms above and confirm your acceptance by
                      <strong style="color: #0f172a;">${responseDeadline ? escapeHtml(responseDeadline) : '[Response Deadline]'}</strong>.
                      You may sign below or reply to this email to indicate your acceptance.
                    </p>
                  </td>
                </tr>

                ${acceptanceBlock}
                ${hrSignatureBlock}

                <!-- Help note -->
                <tr>
                  <td style="padding-top: 24px;">
                    <p style="margin: 0; color: #64748b; font-size: 13px; line-height: 1.6;">
                      Questions? Contact
                      <a href="mailto:${hrEmail}" style="color: #4f46e5; text-decoration: none; font-weight: 500;">${hrEmail}</a>.
                      If you did not apply for this position, please disregard this email.
                    </p>
                  </td>
                </tr>

              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 48px; background: #ffffff; border-top: 1px solid #e5e7eb;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center">
                    <p style="margin: 0 0 4px 0; color: #0f172a; font-size: 13px; font-weight: 600; letter-spacing: -0.1px;">
                      homehealth.ai
                    </p>
                    <p style="margin: 0 0 10px 0; color: #94a3b8; font-size: 12px;">
                      AI-Powered Healthcare Management Platform
                    </p>
                    <p style="margin: 0; color: #94a3b8; font-size: 11px;">
                      &copy; 2026 homehealth.ai &nbsp;·&nbsp;
                      <a href="#" style="color: #94a3b8; text-decoration: underline;">Privacy</a> &nbsp;·&nbsp;
                      <a href="#" style="color: #94a3b8; text-decoration: underline;">Terms</a>
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

    // ── Plain-text fallback ──────────────────────────────────────────────────
    const textLines = [
      subject,
      '',
      `Dear ${applicantName},`,
      '',
      `We are pleased to extend an offer for the position of ${jobTitle}${organizationName ? ` at ${organizationName}` : ''}.`,
      '',
      'OFFER DETAILS',
      jobTitle         ? `  Position:         ${jobTitle}`         : '',
      employmentLabel  ? `  Employment Type:  ${employmentLabel}`  : '',
      jobLocation      ? `  Location:         ${jobLocation}`      : '',
      salary           ? `  Annual Salary:    ${salary}`           : '',
      startDate        ? `  Start Date:       ${startDate}`        : '',
      responseDeadline ? `  Respond By:       ${responseDeadline}` : '',
    ];

    if (benefits?.trim())       textLines.push('', 'BENEFITS & PERKS',     benefits.trim());
    if (jobDescription?.trim()) textLines.push('', 'ABOUT THE ROLE',       truncate(jobDescription, 600));
    if (offerContent?.trim())   textLines.push('', 'OFFER LETTER',         offerContent.trim());
    if (message?.trim())        textLines.push('', 'A NOTE FROM THE TEAM', message.trim());
    if (attachmentUrl)          textLines.push('', `Download Offer Letter: ${attachmentUrl}`);

    if (contactName || contactEmail || contactPhone) {
      textLines.push('', 'YOUR CONTACT');
      if (contactName)  textLines.push(`  ${contactName}`);
      if (contactEmail) textLines.push(`  ${contactEmail}`);
      if (contactPhone) textLines.push(`  ${contactPhone}`);
    }

    textLines.push(
      '',
      responseDeadline
        ? `Please respond to this offer by ${responseDeadline}.`
        : 'Please respond to this offer at your earliest convenience.',
      'If you have any questions, simply reply to this email.',
      '',
      '---',
      `${organizationName ? `${organizationName} – ` : ''}homehealth.ai`,
      'AI-Powered Healthcare Management Platform',
      '© 2026 homehealth.ai. All rights reserved.',
    );

    const text = textLines.filter((l) => l !== undefined && l !== null).join('\n');

    return { subject, html, text };
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

function benefitsTiles(benefits: string): string {
  const items = benefits
    .split(/[\n,]+/)
    .map((b) => b.trim())
    .filter(Boolean);

  return items
    .map(
      (item) => `
      <tr>
        <td style="padding: 4px 0; vertical-align: top;">
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
            <tr>
              <td valign="top" style="width: 16px; padding-right: 10px; color: #059669; font-size: 13px; font-weight: 700; line-height: 1.6;">&#10003;</td>
              <td style="color: #374151; font-size: 13px; line-height: 1.6;">${escapeHtml(item)}</td>
            </tr>
          </table>
        </td>
      </tr>`,
    )
    .join('');
}

function formatEmploymentType(t?: string): string {
  if (!t) return '';
  switch (t) {
    case 'full_time':  return 'Full-time';
    case 'part_time':  return 'Part-time';
    case 'contract':   return 'Contract';
    case 'temporary':  return 'Temporary';
    case 'internship': return 'Internship';
    default:           return t.replace(/_/g, ' ');
  }
}

function firstName(name: string): string {
  return name.trim().split(/\s+/)[0] || name;
}

function initials(name: string): string {
  return name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? '')
    .join('');
}

function truncate(s: string, max: number): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max).trimEnd()}…` : t;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
