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
      ? `Offer letter – ${jobTitle} at ${organizationName}`
      : `Offer letter – ${jobTitle}`;

    const employmentLabel = formatEmploymentType(employmentType);

    const detailRows: string[] = [];
    if (salary) detailRows.push(detailRow('Salary', escapeHtml(salary)));
    if (startDate) detailRows.push(detailRow('Start date', escapeHtml(startDate)));
    if (employmentLabel) detailRows.push(detailRow('Employment type', escapeHtml(employmentLabel)));
    if (jobLocation) detailRows.push(detailRow('Location', escapeHtml(jobLocation)));
    if (responseDeadline) detailRows.push(detailRow('Respond by', escapeHtml(responseDeadline)));

    const detailsBlock = detailRows.length
      ? `
                <tr>
                  <td style="padding: 20px; background: #f0fdf4; border-radius: 12px; border: 1px solid #bbf7d0;">
                    <p style="margin: 0 0 12px 0; color: #166534; font-size: 13px; font-weight: 700; letter-spacing: 0.3px; text-transform: uppercase;">Offer details</p>
                    ${detailRows.join('\n                    ')}
                  </td>
                </tr>`
      : '';

    const benefitsBlock = benefits?.trim()
      ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0 0 8px 0; color: #111827; font-size: 14px; font-weight: 700;">Benefits & perks</p>
                    <div style="padding: 14px 16px; background: #ecfeff; border-left: 3px solid #06b6d4; border-radius: 6px; color: #374151; font-size: 14px; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(benefits).replace(/\n/g, '<br>')}</div>
                  </td>
                </tr>`
      : '';

    const descriptionBlock = jobDescription?.trim()
      ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0 0 6px 0; color: #111827; font-size: 14px; font-weight: 700;">About the role</p>
                    <div style="color: #374151; font-size: 14px; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(truncate(jobDescription, 600))}</div>
                  </td>
                </tr>`
      : '';

    const contentBlock = offerContent?.trim()
      ? `
                <tr>
                  <td style="padding: 20px 0 0 0;">
                    <p style="margin: 0 0 8px 0; color: #111827; font-size: 14px; font-weight: 700;">Offer letter</p>
                    <div style="color: #374151; font-size: 15px; line-height: 1.7; white-space: pre-wrap;">${escapeHtml(offerContent).replace(/\n/g, '<br>')}</div>
                  </td>
                </tr>`
      : '';

    const messageBlock = message?.trim()
      ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0 0 6px 0; color: #111827; font-size: 14px; font-weight: 700;">A note from the team</p>
                    <div style="padding: 14px 16px; background: #fefce8; border-left: 3px solid #facc15; border-radius: 6px; color: #374151; font-size: 15px; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(message)}</div>
                  </td>
                </tr>`
      : '';

    const attachmentBlock = attachmentUrl
      ? `
                <tr>
                  <td style="padding: 20px 0 0 0;">
                    <p style="margin: 0 0 10px 0; color: #6b7280; font-size: 14px;">Attached offer letter:</p>
                    <a href="${attachmentUrl}" style="display:inline-block;padding:10px 18px;background:#16a34a;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;border-radius:8px;">Download offer letter</a>
                  </td>
                </tr>`
      : '';

    const contactBlock =
      contactName || contactEmail || contactPhone
        ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0 0 6px 0; color: #111827; font-size: 14px; font-weight: 700;">Your contact</p>
                    ${contactName ? `<p style="margin:0;color:#374151;font-size:14px;">${escapeHtml(contactName)}</p>` : ''}
                    ${contactEmail ? `<p style="margin:0;color:#374151;font-size:14px;"><a href="mailto:${escapeHtml(contactEmail)}" style="color:#2563eb;text-decoration:none;">${escapeHtml(contactEmail)}</a></p>` : ''}
                    ${contactPhone ? `<p style="margin:0;color:#374151;font-size:14px;">${escapeHtml(contactPhone)}</p>` : ''}
                  </td>
                </tr>`
        : '';

    const orgLine = organizationName
      ? `at <strong>${escapeHtml(organizationName)}</strong>`
      : '';

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${subject}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="padding: 40px 20px;">
    <tr>
      <td align="center">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; width: 100%; background: #ffffff; border-radius: 16px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); overflow: hidden;">
          <tr>
            <td style="height: 4px; background: linear-gradient(90deg, #16a34a 0%, #22c55e 100%);"></td>
          </tr>
          <tr>
            <td align="center" style="padding: 32px 40px 0 40px;">
              <img src="cid:logo@homehealth.ai" alt="HomeHealth.AI" width="64" height="64" style="display: block; width: 64px; height: 64px;" />
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 40px 0 40px;">
              <h1 style="margin: 0 0 8px 0; color: #111827; font-size: 22px; font-weight: 700; text-align: center;">Congratulations${applicantName ? `, ${escapeHtml(firstName(applicantName))}` : ''}!</h1>
              <p style="margin: 0 0 24px 0; color: #6b7280; font-size: 15px; text-align:center;">We're excited to extend you an offer.</p>
              <p style="margin: 0 0 20px 0; color: #374151; font-size: 16px; line-height: 1.6;">
                Hello ${escapeHtml(applicantName)}, we are pleased to extend an offer for the position of <strong>${escapeHtml(jobTitle)}</strong> ${orgLine}. Please review the details below.
              </p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                ${detailsBlock}
                ${benefitsBlock}
                ${descriptionBlock}
                ${contentBlock}
                ${messageBlock}
                ${attachmentBlock}
                ${contactBlock}
              </table>
              <p style="margin: 24px 0 0 0; color: #6b7280; font-size: 14px;">${responseDeadline ? `Please respond to this offer by <strong>${escapeHtml(responseDeadline)}</strong>. ` : ''}If you have any questions, simply reply to this email.</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 40px; background: #f9fafb; border-top: 1px solid #e5e7eb;">
              <p style="margin: 0; color: #9ca3af; font-size: 12px;">${organizationName ? `${escapeHtml(organizationName)} – ` : ''}homehealth.ai – Job Applications</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`.trim();

    const textLines = [
      subject,
      '',
      `Hello ${applicantName},`,
      '',
      `We are pleased to extend an offer for the position of ${jobTitle}${organizationName ? ` at ${organizationName}` : ''}.`,
      '',
      'Offer details',
      salary ? `  Salary: ${salary}` : '',
      startDate ? `  Start date: ${startDate}` : '',
      employmentLabel ? `  Employment type: ${employmentLabel}` : '',
      jobLocation ? `  Location: ${jobLocation}` : '',
      responseDeadline ? `  Respond by: ${responseDeadline}` : '',
    ];
    if (benefits?.trim()) {
      textLines.push('', 'Benefits & perks', benefits.trim());
    }
    if (jobDescription?.trim()) {
      textLines.push('', 'About the role', truncate(jobDescription, 600));
    }
    if (offerContent?.trim()) {
      textLines.push('', 'Offer letter', offerContent.trim());
    }
    if (message?.trim()) {
      textLines.push('', 'A note from the team', message.trim());
    }
    if (attachmentUrl) {
      textLines.push('', `Attached offer letter: ${attachmentUrl}`);
    }
    if (contactName || contactEmail || contactPhone) {
      textLines.push('', 'Your contact');
      if (contactName) textLines.push(`  ${contactName}`);
      if (contactEmail) textLines.push(`  ${contactEmail}`);
      if (contactPhone) textLines.push(`  ${contactPhone}`);
    }
    textLines.push(
      '',
      responseDeadline
        ? `Please respond by ${responseDeadline}. If you have any questions, reply to this email.`
        : 'If you have any questions, reply to this email.',
      '',
      '---',
      `${organizationName ? `${organizationName} – ` : ''}homehealth.ai – Job Applications`,
    );
    const text = textLines.filter((l) => l !== undefined && l !== null).join('\n');

    return { subject, html, text };
  }
}

function detailRow(label: string, value: string): string {
  return `<p style="margin: 0 0 6px 0; color: #14532d; font-size: 15px;"><strong style="color:#166534;">${label}:</strong> ${value}</p>`;
}

function formatEmploymentType(t?: string): string {
  if (!t) return '';
  switch (t) {
    case 'full_time':
      return 'Full-time';
    case 'part_time':
      return 'Part-time';
    case 'contract':
      return 'Contract';
    case 'temporary':
      return 'Temporary';
    case 'internship':
      return 'Internship';
    default:
      return t.replace(/_/g, ' ');
  }
}

function firstName(name: string): string {
  return name.trim().split(/\s+/)[0] || name;
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
