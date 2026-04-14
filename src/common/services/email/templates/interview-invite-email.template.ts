export interface InterviewInviteOptions {
  applicantName: string;
  jobTitle: string;
  interviewDate: string;
  interviewTime: string;
  /** "in_person" | "video" | "phone" */
  interviewMode?: string;
  /** Address, video link, or phone number depending on mode */
  interviewLocation?: string;
  interviewDuration?: string;
  message?: string;
  jobLocation?: string;
  jobType?: string;
  salaryRange?: string;
  jobDescription?: string;
  organizationName?: string;
  contactName?: string;
  contactEmail?: string;
  contactPhone?: string;
}

export class InterviewInviteEmailTemplate {
  static generate(opts: InterviewInviteOptions): {
    subject: string;
    html: string;
    text: string;
  } {
    const {
      applicantName,
      jobTitle,
      interviewDate,
      interviewTime,
      interviewMode,
      interviewLocation,
      interviewDuration,
      message,
      jobLocation,
      jobType,
      salaryRange,
      jobDescription,
      organizationName,
      contactName,
      contactEmail,
      contactPhone,
    } = opts;

    const subject = organizationName
      ? `Interview scheduled – ${jobTitle} at ${organizationName}`
      : `Interview scheduled – ${jobTitle}`;

    const modeLabel = formatMode(interviewMode);
    const locationLabel =
      interviewMode === 'video'
        ? 'Meeting link'
        : interviewMode === 'phone'
          ? 'Phone'
          : 'Location';

    const interviewRows: string[] = [];
    if (interviewDate) {
      interviewRows.push(detailRow('Date', escapeHtml(interviewDate)));
    }
    if (interviewTime) {
      interviewRows.push(detailRow('Time', escapeHtml(interviewTime)));
    }
    if (interviewDuration) {
      interviewRows.push(detailRow('Duration', escapeHtml(interviewDuration)));
    }
    if (modeLabel) {
      interviewRows.push(detailRow('Format', escapeHtml(modeLabel)));
    }
    if (interviewLocation) {
      const value =
        interviewMode === 'video' && /^https?:\/\//i.test(interviewLocation)
          ? `<a href="${escapeHtml(interviewLocation)}" style="color:#2563eb;text-decoration:underline;">${escapeHtml(interviewLocation)}</a>`
          : escapeHtml(interviewLocation);
      interviewRows.push(detailRow(locationLabel, value));
    }

    const interviewBlock = interviewRows.length
      ? `
                <tr>
                  <td style="padding: 20px; background: #f0f9ff; border-radius: 12px; border: 1px solid #bae6fd;">
                    <p style="margin: 0 0 12px 0; color: #0369a1; font-size: 13px; font-weight: 700; letter-spacing: 0.3px; text-transform: uppercase;">Interview details</p>
                    ${interviewRows.join('\n                    ')}
                  </td>
                </tr>`
      : '';

    const jobInfoRows: string[] = [];
    if (jobLocation) jobInfoRows.push(detailRow('Location', escapeHtml(jobLocation)));
    if (jobType) jobInfoRows.push(detailRow('Type', escapeHtml(jobType)));
    if (salaryRange) jobInfoRows.push(detailRow('Salary range', escapeHtml(salaryRange)));
    const jobInfoBlock = jobInfoRows.length
      ? `
                <tr>
                  <td style="padding: 16px 20px; background: #f9fafb; border-radius: 12px; border: 1px solid #e5e7eb; margin-top: 12px;">
                    <p style="margin: 0 0 10px 0; color: #374151; font-size: 13px; font-weight: 700; letter-spacing: 0.3px; text-transform: uppercase;">About this role</p>
                    ${jobInfoRows.join('\n                    ')}
                  </td>
                </tr>`
      : '';

    const descriptionBlock = jobDescription?.trim()
      ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0 0 6px 0; color: #111827; font-size: 14px; font-weight: 700;">Job summary</p>
                    <div style="color: #374151; font-size: 14px; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(truncate(jobDescription, 600))}</div>
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
            <td style="height: 4px; background: linear-gradient(90deg, #2563eb 0%, #0ea5e9 100%);"></td>
          </tr>
          <tr>
            <td align="center" style="padding: 32px 40px 0 40px;">
              <img src="cid:logo@homehealth.ai" alt="HomeHealth.AI" width="64" height="64" style="display: block; width: 64px; height: 64px;" />
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 40px 0 40px;">
              <h1 style="margin: 0 0 8px 0; color: #111827; font-size: 22px; font-weight: 700; text-align: center;">Interview scheduled</h1>
              <p style="margin: 0 0 24px 0; color: #6b7280; font-size: 15px;">Hello ${escapeHtml(applicantName)},</p>
              <p style="margin: 0 0 20px 0; color: #374151; font-size: 16px; line-height: 1.6;">
                Thank you for applying for the position of <strong>${escapeHtml(jobTitle)}</strong> ${orgLine}. We're excited to learn more about you and have scheduled the interview below.
              </p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                ${interviewBlock}
                ${jobInfoBlock}
                ${descriptionBlock}
                ${messageBlock}
                ${contactBlock}
              </table>
              <p style="margin: 24px 0 0 0; color: #6b7280; font-size: 14px;">Please reply to this email to confirm your attendance or to reschedule. We look forward to speaking with you.</p>
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
      `Thank you for applying for the position of ${jobTitle}${organizationName ? ` at ${organizationName}` : ''}. We have scheduled your interview as follows:`,
      '',
      'Interview details',
      interviewDate ? `  Date: ${interviewDate}` : '',
      interviewTime ? `  Time: ${interviewTime}` : '',
      interviewDuration ? `  Duration: ${interviewDuration}` : '',
      modeLabel ? `  Format: ${modeLabel}` : '',
      interviewLocation ? `  ${locationLabel}: ${interviewLocation}` : '',
    ];
    if (jobLocation || jobType || salaryRange) {
      textLines.push('', 'About this role');
      if (jobLocation) textLines.push(`  Location: ${jobLocation}`);
      if (jobType) textLines.push(`  Type: ${jobType}`);
      if (salaryRange) textLines.push(`  Salary range: ${salaryRange}`);
    }
    if (jobDescription?.trim()) {
      textLines.push('', 'Job summary', truncate(jobDescription, 600));
    }
    if (message?.trim()) {
      textLines.push('', 'A note from the team', message.trim());
    }
    if (contactName || contactEmail || contactPhone) {
      textLines.push('', 'Your contact');
      if (contactName) textLines.push(`  ${contactName}`);
      if (contactEmail) textLines.push(`  ${contactEmail}`);
      if (contactPhone) textLines.push(`  ${contactPhone}`);
    }
    textLines.push(
      '',
      'Please reply to this email to confirm your attendance or to reschedule.',
      '',
      '---',
      `${organizationName ? `${organizationName} – ` : ''}homehealth.ai – Job Applications`,
    );
    const text = textLines.filter((l) => l !== undefined && l !== null).join('\n');

    return { subject, html, text };
  }
}

function detailRow(label: string, value: string): string {
  return `<p style="margin: 0 0 6px 0; color: #0c4a6e; font-size: 15px;"><strong style="color:#0369a1;">${label}:</strong> ${value}</p>`;
}

function formatMode(mode?: string): string {
  if (!mode) return '';
  switch (mode) {
    case 'in_person':
      return 'In-person';
    case 'video':
      return 'Video call';
    case 'phone':
      return 'Phone';
    default:
      return mode.replace(/_/g, ' ');
  }
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
