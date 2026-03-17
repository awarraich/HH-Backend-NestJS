function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export class OfferLetterEmailTemplate {
  static generate(
    applicantName: string,
    jobTitle: string,
    salary: string,
    startDate: string,
    offerContent: string,
    attachmentUrl?: string,
  ): {
    subject: string;
    html: string;
    text: string;
  } {
    const subject = `Offer letter – ${jobTitle}`;
    const detailsBlock =
      salary || startDate
        ? `
                <tr>
                  <td style="padding: 20px; background: #f0fdf4; border-radius: 12px; border: 1px solid #bbf7d0;">
                    <p style="margin: 0 0 8px 0; color: #166534; font-size: 13px; font-weight: 700;">Offer details</p>
                    ${salary ? `<p style="margin: 0 0 4px 0; color: #14532d; font-size: 16px;"><strong>Salary:</strong> ${escapeHtml(salary)}</p>` : ''}
                    ${startDate ? `<p style="margin: 0; color: #14532d; font-size: 16px;"><strong>Start date:</strong> ${escapeHtml(startDate)}</p>` : ''}
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
    const attachmentBlock = attachmentUrl
      ? `
                <tr>
                  <td style="padding: 16px 0 0 0;">
                    <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 14px;">Attached offer letter:</p>
                    <a href="${attachmentUrl}" style="color: #2563eb; font-size: 14px; text-decoration: underline;">Download offer letter</a>
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
            <td style="height: 4px; background: linear-gradient(90deg, #16a34a 0%, #22c55e 100%);"></td>
          </tr>
          <tr>
            <td align="center" style="padding: 32px 40px 0 40px;">
              <img src="cid:logo@homehealth.ai" alt="HomeHealth.AI" width="64" height="64" style="display: block; width: 64px; height: 64px;" />
            </td>
          </tr>
          <tr>
            <td style="padding: 24px 40px 0 40px;">
              <h1 style="margin: 0 0 8px 0; color: #111827; font-size: 22px; font-weight: 700; text-align: center;">Offer letter</h1>
              <p style="margin: 0 0 24px 0; color: #6b7280; font-size: 15px;">Hello ${escapeHtml(applicantName)},</p>
              <p style="margin: 0 0 16px 0; color: #374151; font-size: 16px; line-height: 1.6;">
                We are pleased to extend an offer for the position of <strong>${escapeHtml(jobTitle)}</strong>.
              </p>
              ${detailsBlock}
              ${contentBlock}
              ${attachmentBlock}
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

    const textLines = [
      `Offer letter – ${jobTitle}`,
      '',
      `Hello ${applicantName},`,
      '',
      `We are pleased to extend an offer for the position of ${jobTitle}.`,
      salary ? `Salary: ${salary}` : '',
      startDate ? `Start date: ${startDate}` : '',
      offerContent?.trim() ? `\nOffer letter:\n${offerContent.trim()}` : '',
      attachmentUrl ? `\nAttached offer letter: ${attachmentUrl}` : '',
      '',
      'If you have any questions, please reply to this email.',
      '',
      '---',
      'homehealth.ai – Job Applications',
    ].filter(Boolean);
    const text = textLines.join('\n');

    return { subject, html, text };
  }
}
