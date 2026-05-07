/**
 * "Action needed: fill out competency document" email — sent once per role
 * row when HR assigns a competency template to an employee. Mirrors the
 * branding chrome used by `offer-letter-email.template.ts` so the per-org
 * logo (CID `logo@homehealth.ai`) drops in via the standard attachment.
 *
 * Each recipient gets a CTA pointing at their portion of the document:
 *   - employee   → `/competency/open?to=/employee/competency?...`
 *   - supervisor → `/competency/open?to=/organization/document-workflow?...`
 *   - external   → `/competency/fill/<token>` (public token-gated page)
 */

export type CompetencyRecipientKind =
  | 'supervisor'
  | 'employee'
  | 'external_employee';

export interface CompetencyFillEmailOptions {
  /** Greeting name — the role-filler being asked to fill their portion. */
  recipientName: string;
  /** Whose HR file this template is being filled against. */
  employeeName?: string;
  /** Display name of the role the recipient is assigned to. */
  roleName: string;
  /** Template name (e.g., "Annual Competency Review"). */
  templateName: string;
  /** Optional template description for body context. */
  templateDescription?: string;
  organizationName?: string;
  /** Deep link the recipient should follow to fill their fields. */
  fillUrl: string;
  /** Routing hint — drives copy. */
  recipientType: CompetencyRecipientKind;
}

function escapeHtml(value: string): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export class CompetencyFillEmailTemplate {
  static generate(opts: CompetencyFillEmailOptions): {
    subject: string;
    html: string;
    text: string;
  } {
    const {
      recipientName,
      employeeName,
      roleName,
      templateName,
      templateDescription,
      organizationName,
      fillUrl,
      recipientType,
    } = opts;

    const brandName = organizationName?.trim() || 'homehealth.ai';
    const logoAlt = escapeHtml(brandName);

    const isSelf = recipientType === 'employee' && (!employeeName || employeeName === recipientName);
    const targetCopy = isSelf
      ? 'your competency document'
      : employeeName
        ? `${employeeName}'s competency document`
        : 'this competency document';

    const subject = organizationName
      ? `Action needed: Fill ${escapeHtml(templateName)} (${roleName}) at ${organizationName}`
      : `Action needed: Fill ${escapeHtml(templateName)} (${roleName})`;

    const preheader = `${recipientName}, please fill the ${roleName} fields on ${targetCopy}.`;

    const logoBlock = `
                    <img src="cid:logo@homehealth.ai" alt="${logoAlt}" width="80" height="80" style="display: block; width: 80px; height: 80px; margin: 0 auto;" />`;

    const tokenNote =
      recipientType === 'external_employee'
        ? `<p style="margin: 0 0 16px 0; color: #64748b; font-size: 13px; line-height: 1.6;">This link is unique to you and does not require a login. Please don't share it.</p>`
        : `<p style="margin: 0 0 16px 0; color: #64748b; font-size: 13px; line-height: 1.6;">You'll be asked to log in if your session has expired.</p>`;

    const descriptionBlock = templateDescription?.trim()
      ? `<p style="margin: 0 0 16px 0; color: #475569; font-size: 14px; line-height: 1.6;">${escapeHtml(templateDescription)}</p>`
      : '';

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>${escapeHtml(templateName)} – ${escapeHtml(brandName)}</title>
  <style type="text/css">
    @media only screen and (max-width: 600px) {
      .eml-container { width: 100% !important; max-width: 100% !important; border-radius: 0 !important; border-left: 0 !important; border-right: 0 !important; }
      .eml-pad { padding: 20px !important; }
      .eml-header-pad { padding: 28px 20px 20px 20px !important; }
      .eml-body-pad { padding: 24px 20px 28px 20px !important; }
      .eml-cta { padding: 12px 20px !important; }
      .eml-h1 { font-size: 20px !important; line-height: 1.25 !important; }
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <div style="display: none; max-height: 0; overflow: hidden;">${escapeHtml(preheader)}</div>
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" class="eml-container" style="max-width: 600px; width: 100%; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #4f46e5 0%, #06b6d4 100%);"></td>
          </tr>
          <tr>
            <td class="eml-header-pad" style="padding: 40px 48px 28px 48px; text-align: center; background-color: #ffffff; border-bottom: 1px solid #f1f5f9;">
              ${logoBlock}
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 14px auto 14px auto;">
                <tr>
                  <td style="background: #eff6ff; border: 1px solid #c7d2fe; border-radius: 24px; padding: 5px 16px;">
                    <span style="font-size: 11px; font-weight: 700; color: #4338ca; letter-spacing: 1px;">ACTION NEEDED</span>
                  </td>
                </tr>
              </table>
              <h1 class="eml-h1" style="margin: 0; color: #0f172a; font-size: 24px; font-weight: 700; line-height: 1.3; letter-spacing: -0.3px;">
                ${escapeHtml(templateName)}
              </h1>
              ${organizationName ? `<p style="margin: 6px 0 0 0; color: #64748b; font-size: 14px; line-height: 1.5;">${escapeHtml(organizationName)}</p>` : ''}
              ${!isSelf && employeeName ? `<p style="margin: 4px 0 0 0; color: #64748b; font-size: 13px;">For: <strong style="color:#0f172a;">${escapeHtml(employeeName)}</strong></p>` : ''}
            </td>
          </tr>
          <tr>
            <td class="eml-body-pad" style="padding: 32px 48px 36px 48px;">
              <p style="margin: 0 0 12px 0; color: #0f172a; font-size: 16px; line-height: 1.6;">Hi ${escapeHtml(recipientName)},</p>
              <p style="margin: 0 0 16px 0; color: #475569; font-size: 14px; line-height: 1.6;">
                You've been asked to fill the <strong style="color:#0f172a;">${escapeHtml(roleName)}</strong> fields on ${escapeHtml(targetCopy)}.
              </p>
              ${descriptionBlock}
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 24px auto 16px auto;">
                <tr>
                  <td style="background: #4f46e5; border-radius: 6px;">
                    <a href="${escapeHtml(fillUrl)}" class="eml-cta" style="display: inline-block; padding: 14px 28px; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 600; letter-spacing: 0.2px;">
                      Open document
                    </a>
                  </td>
                </tr>
              </table>
              ${tokenNote}
              <p style="margin: 0; color: #94a3b8; font-size: 12px; line-height: 1.6; word-break: break-all;">
                If the button doesn't work, paste this link into your browser:<br />
                <a href="${escapeHtml(fillUrl)}" style="color: #4f46e5;">${escapeHtml(fillUrl)}</a>
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 18px 48px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; text-align: center;">
              <p style="margin: 0; color: #94a3b8; font-size: 11px; line-height: 1.6;">
                This is an automated message from ${escapeHtml(brandName)}. Replies aren't monitored.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `;

    const text = [
      `Hi ${recipientName},`,
      '',
      `You've been asked to fill the ${roleName} fields on ${targetCopy}.`,
      templateDescription ? '' : null,
      templateDescription ? templateDescription : null,
      '',
      `Open: ${fillUrl}`,
      '',
      recipientType === 'external_employee'
        ? "This link is unique to you and does not require a login."
        : "You'll be asked to log in if your session has expired.",
    ]
      .filter((line) => line !== null)
      .join('\n');

    return { subject, html, text };
  }
}
