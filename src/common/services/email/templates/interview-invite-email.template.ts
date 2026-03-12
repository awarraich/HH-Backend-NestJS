export class InterviewInviteEmailTemplate {
  static generate(
    applicantName: string,
    jobTitle: string,
    interviewDate: string,
    interviewTime: string,
    message?: string,
  ): {
    subject: string;
    html: string;
    text: string;
  } {
    const subject = `Interview scheduled – ${jobTitle}`;
    const dateTimeBlock =
      interviewDate || interviewTime
        ? `
                <tr>
                  <td style="padding: 20px; background: #f0f9ff; border-radius: 12px; border: 1px solid #bae6fd;">
                    <p style="margin: 0 0 8px 0; color: #0369a1; font-size: 13px; font-weight: 700;">Interview details</p>
                    ${interviewDate ? `<p style="margin: 0 0 4px 0; color: #0c4a6e; font-size: 16px;"><strong>Date:</strong> ${escapeHtml(interviewDate)}</p>` : ''}
                    ${interviewTime ? `<p style="margin: 0; color: #0c4a6e; font-size: 16px;"><strong>Time:</strong> ${escapeHtml(interviewTime)}</p>` : ''}
                  </td>
                </tr>`
        : '';
    const extraMessage = message?.trim()
      ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.6; white-space: pre-wrap;">${escapeHtml(message)}</p>
                  </td>
                </tr>`
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
            <td style="padding: 32px 40px;">
              <h1 style="margin: 0 0 8px 0; color: #111827; font-size: 22px; font-weight: 700;">Interview scheduled</h1>
              <p style="margin: 0 0 24px 0; color: #6b7280; font-size: 15px;">Hello ${escapeHtml(applicantName)},</p>
              <p style="margin: 0 0 16px 0; color: #374151; font-size: 16px; line-height: 1.6;">
                You have been scheduled for an interview for the position of <strong>${escapeHtml(jobTitle)}</strong>.
              </p>
              ${dateTimeBlock}
              ${extraMessage}
              <p style="margin: 24px 0 0 0; color: #6b7280; font-size: 14px;">If you have any questions, please reply to this email.</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 40px; background: #f9fafb; border-top: 1px solid #e5e7eb;">
              <p style="margin: 0; color: #9ca3af; font-size: 12px;">homehealth.ai – Job Applications</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`.trim();

    const text = [
      `Interview scheduled – ${jobTitle}`,
      '',
      `Hello ${applicantName},`,
      '',
      `You have been scheduled for an interview for the position of ${jobTitle}.`,
      interviewDate ? `Date: ${interviewDate}` : '',
      interviewTime ? `Time: ${interviewTime}` : '',
      message?.trim() ? `\n${message.trim()}` : '',
      '',
      'If you have any questions, please reply to this email.',
      '',
      '---',
      'homehealth.ai – Job Applications',
    ]
      .filter(Boolean)
      .join('\n');

    return { subject, html, text };
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
