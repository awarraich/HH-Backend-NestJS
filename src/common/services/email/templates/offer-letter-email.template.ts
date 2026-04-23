export type OfferRecipientKind =
  | 'supervisor'
  | 'employee'
  | 'external_employee'
  | 'applicant';

export interface OfferLetterOptions {
  /**
   * The recipient's name. For signer emails (supervisor / employee /
   * external / CEO), this is the signer — not the candidate; we use it for
   * the greeting ("Dear HR Lead,"). When `recipientType === 'applicant'`,
   * the recipient *is* the candidate, and both `applicantName` and
   * `candidateName` refer to the same person.
   */
  applicantName: string;
  /**
   * The job candidate's name. Required on signer emails so the message can
   * reference the person whose offer letter they're being asked to sign
   * (distinct from the recipient). Falls back to `applicantName` when
   * omitted — matches legacy callers that treated the two as one field.
   */
  candidateName?: string;
  jobTitle: string;
  salary: string;
  startDate: string;
  offerContent: string;
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
  /** URL where the recipient fills/reviews the offer letter document. */
  fillUrl?: string;
  /**
   * Drives the layout — applicants get the full offer (salary / benefits /
   * acceptance signature block); signers (supervisor, employee filling a
   * role, external_employee with a token, or unspecified) get a shorter,
   * action-focused layout that omits compensation details.
   */
  recipientType?: OfferRecipientKind;
}

export class OfferLetterEmailTemplate {
  static generate(opts: OfferLetterOptions): {
    subject: string;
    html: string;
    text: string;
  } {
    const {
      applicantName,
      candidateName: candidateNameOpt,
      jobTitle,
      salary,
      startDate,
      offerContent,
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
      fillUrl,
      recipientType,
    } = opts;

    const brandName = organizationName?.trim() || 'homehealth.ai';
    const logoAlt = escapeHtml(brandName);
    const isApplicant = recipientType === 'applicant';
    const candidateName = candidateNameOpt?.trim() || applicantName;

    // Subject and preheader switch on recipient so a supervisor's inbox
    // preview doesn't read "Congratulations on your new role" when they
    // didn't actually get the role.
    const subject = isApplicant
      ? organizationName
        ? `Your Offer Letter – ${jobTitle} at ${organizationName}`
        : `Your Offer Letter – ${jobTitle}`
      : organizationName
        ? `Action needed: Sign offer letter for ${candidateName} (${jobTitle}) at ${organizationName}`
        : `Action needed: Sign offer letter for ${candidateName} (${jobTitle})`;

    const preheader = isApplicant
      ? `Congratulations! Your offer for ${jobTitle}${organizationName ? ` at ${organizationName}` : ''} is ready to review and accept.`
      : `${candidateName}'s offer letter for ${jobTitle}${organizationName ? ` at ${organizationName}` : ''} is ready for your signature.`;

    const employmentLabel = formatEmploymentType(employmentType);
    const orgLine = organizationName
      ? `at <strong style="color:#0f172a;">${escapeHtml(organizationName)}</strong>`
      : '';
    const hrEmail = contactEmail ? escapeHtml(contactEmail) : 'hr@homehealth.ai';

    // ── Logo block — exact same treatment as the Organization Staff
    // Created email: plain 80x80 inline image, no colored wrapper. The
    // CID is attached by `EmailService.buildLogoAttachment()` so the
    // per-org logo overrides the default when uploaded.
    const logoBlock = `
                    <img src="cid:logo@homehealth.ai" alt="${logoAlt}" width="80" height="80" style="display: block; width: 80px; height: 80px; margin: 0 auto;" />`;

    // ── Role rows — shared by both layouts (signers need job-context too) ───
    const roleRows: string[] = [];
    if (jobTitle)        roleRows.push(tableRow('Position',        escapeHtml(jobTitle),        '#e5e7eb'));
    if (employmentLabel) roleRows.push(tableRow('Employment Type', escapeHtml(employmentLabel), '#e5e7eb'));
    if (jobLocation)     roleRows.push(tableRow('Location',        escapeHtml(jobLocation),     '#e5e7eb'));
    if (!isApplicant && candidateName)
      roleRows.push(tableRow('Candidate', escapeHtml(candidateName), '#e5e7eb'));

    const roleBlock = roleRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Role', '#4f46e5', roleRows.join(''))}</td></tr>`
      : '';

    // ── Key dates — applicant only ──────────────────────────────────────────
    const startRows: string[] = [];
    if (startDate)        startRows.push(tableRow('Start Date',  escapeHtml(startDate),        '#e5e7eb'));
    if (responseDeadline) startRows.push(tableRow('Respond By',  escapeHtml(responseDeadline), '#e5e7eb'));
    const startBlock = isApplicant && startRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Key Dates', '#0891b2', startRows.join(''))}</td></tr>`
      : '';

    // ── Salary + benefits — applicant only (private compensation data) ──────
    const salaryRows: string[] = [];
    if (salary) salaryRows.push(tableRow('Annual Salary',     escapeHtml(salary),            '#e5e7eb'));
    salaryRows.push(        tableRow('Payment Schedule', 'Monthly (last working day)',       '#e5e7eb'));
    salaryRows.push(        tableRow('Probation Period',  '3 months',                        '#e5e7eb'));
    const salaryBlock = isApplicant && salary
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Compensation', '#059669', salaryRows.join(''))}</td></tr>`
      : '';

    const benefitsBlock = isApplicant && benefits?.trim()
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Benefits', '#7c3aed', benefitsTiles(benefits))}</td></tr>`
      : '';

    // ── Job description — applicant only ─────────────────────────────────────
    const descriptionBlock = isApplicant && jobDescription?.trim()
      ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('About the Role', '#475569', `<tr><td style="color:#374151;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(truncate(jobDescription, 600))}</td></tr>`)}
                  </td>
                </tr>`
      : '';

    // ── Offer content — applicant only ───────────────────────────────────────
    const contentBlock = isApplicant && offerContent?.trim()
      ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('Offer Letter', '#0f172a', `<tr><td style="color:#374151;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(offerContent).replace(/\n/g, '<br>')}</td></tr>`)}
                  </td>
                </tr>`
      : '';

    // ── Team message — applicant only ────────────────────────────────────────
    const messageBlock = isApplicant && message?.trim()
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

    // ── CTA block — recipient-aware copy + colour ───────────────────────────
    const fillCopy = buildFillCopy(recipientType, fillUrl);
    const ctaBg = isApplicant ? '#eef2ff' : '#fef3c7';
    const ctaBorder = isApplicant ? '#c7d2fe' : '#fcd34d';
    const ctaLabelColor = isApplicant ? '#4338ca' : '#92400e';
    const ctaBodyColor = isApplicant ? '#1e1b4b' : '#78350f';
    const ctaButtonColor = isApplicant ? '#4f46e5' : '#d97706';
    const fillBlock = fillUrl
      ? `
                <tr>
                  <td style="padding: 8px 0 28px 0;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:${ctaBg};border:1px solid ${ctaBorder};border-radius:8px;">
                      <tr>
                        <td class="eml-pad" style="padding: 24px 28px;">
                          <p style="margin: 0 0 6px 0; font-size: 11px; font-weight: 700; color: ${ctaLabelColor}; letter-spacing: 0.8px; text-transform: uppercase;">${fillCopy.heading}</p>
                          <p style="margin: 0 0 16px 0; color: ${ctaBodyColor}; font-size: 14px; line-height: 1.6;">
                            ${escapeHtml(fillCopy.body)}
                          </p>
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                              <td style="border-radius: 6px; background: ${ctaButtonColor};">
                                <a href="${escapeHtml(fillUrl)}" target="_blank" class="eml-cta" style="display: inline-block; padding: 14px 32px; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 6px; letter-spacing: 0.2px;">
                                  ${escapeHtml(fillCopy.cta)}
                                </a>
                              </td>
                            </tr>
                          </table>
                          <p style="margin: 14px 0 0 0; color: #475569; font-size: 12px; line-height: 1.6;">
                            ${escapeHtml(fillCopy.footer)}<br/>
                            <span style="color:${ctaLabelColor};word-break:break-all;">${escapeHtml(fillUrl)}</span>
                          </p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>`
      : '';

    // ── Contact block — shared ──────────────────────────────────────────────
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

    // Candidate acceptance used to render a paper-style signature block
    // (Candidate Signature / Date / Printed Name / Personal Email lines)
    // here. Now that the applicant e-signs the actual offer letter PDF
    // in-app — and we capture signature + IP + geolocation in
    // `offer_details.applicantSignature` — the email no longer needs to
    // duplicate that ceremony. Left as an empty string so the template
    // layout below stays unchanged.
    const acceptanceBlock = '';

    // ── HR signature block — shared ─────────────────────────────────────────
    const hrSignatureBlock = `
                <tr>
                  <td style="padding-top: 24px; border-top: 1px solid #e5e7eb;">
                    <p style="font-size:11px;font-weight:700;color:#475569;margin:0 0 6px 0;letter-spacing:0.8px;text-transform:uppercase;">
                      Authorized by ${escapeHtml(brandName)}
                    </p>
                    <div style="border-bottom:1px solid #cbd5e1;width:180px;margin:16px 0 8px;"></div>
                    ${contactName ? `<p style="font-size:14px;font-weight:600;color:#0f172a;margin:0 0 2px;">${escapeHtml(contactName)}</p>` : ''}
                    <p style="font-size:13px;color:#64748b;margin:0 0 2px;">Head of Human Resources</p>
                    <p style="font-size:13px;margin:0;"><a href="mailto:${hrEmail}" style="color:#4f46e5;text-decoration:none;">${hrEmail}</a></p>
                  </td>
                </tr>`;

    // ── Greeting + intro — recipient-aware ──────────────────────────────────
    const greetingHtml = `
                <tr>
                  <td style="padding-bottom: 12px;">
                    <p style="margin: 0; color: #0f172a; font-size: 16px; line-height: 1.6;">
                      Dear ${escapeHtml(applicantName)},
                    </p>
                  </td>
                </tr>`;

    const introHtml = isApplicant
      ? `
                <tr>
                  <td style="padding-bottom: 28px;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.7;">
                      Following our review of your application and interview, we are pleased to extend an offer for the position of
                      <strong style="color: #0f172a;">${escapeHtml(jobTitle)}</strong> ${orgLine}.
                      The complete terms of this offer are outlined below for your consideration.
                    </p>
                  </td>
                </tr>`
      : `
                <tr>
                  <td style="padding-bottom: 28px;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.7;">
                      You've been asked to review and sign the offer letter prepared for
                      <strong style="color: #0f172a;">${escapeHtml(candidateName)}</strong> for the role of
                      <strong style="color: #0f172a;">${escapeHtml(jobTitle)}</strong> ${orgLine}.
                      Open the document using the button below to add your signature and return it to HR.
                    </p>
                  </td>
                </tr>`;

    const closingHtml = isApplicant
      ? `
                <tr>
                  <td style="padding: 8px 0 24px 0;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.7;">
                      ${
                        responseDeadline
                          ? `Please review the terms and confirm your acceptance by <strong style="color: #0f172a;">${escapeHtml(responseDeadline)}</strong>. Open the offer using the button above to sign electronically, or reply to this email with any questions.`
                          : `Open the offer using the button above to review the full terms and sign electronically. Reply to this email if you have any questions — we'd be delighted to hear from you.`
                      }
                    </p>
                  </td>
                </tr>`
      : `
                <tr>
                  <td style="padding: 8px 0 24px 0;">
                    <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.7;">
                      If you have questions about this document, reply to this email or reach
                      out to the hiring team directly. Your signature helps us finalise
                      ${escapeHtml(candidateName)}'s onboarding as quickly as possible.
                    </p>
                  </td>
                </tr>`;

    const headerChipLabel = isApplicant ? 'OFFER OF EMPLOYMENT' : 'ACTION REQUIRED · SIGNATURE';

    // ── Full HTML ────────────────────────────────────────────────────────────
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>${isApplicant ? 'Your Offer Letter' : 'Action Needed: Sign Offer Letter'} – ${escapeHtml(jobTitle)} – ${escapeHtml(brandName)}</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
  <style type="text/css">
    /* Mobile-first fallback: most modern clients honour this. The outer
       container caps at 600px on desktop; here we shrink padding and stack
       two-column rows for narrow screens so the CTA and signature lines
       remain tappable on phones. */
    @media only screen and (max-width: 600px) {
      .eml-container { width: 100% !important; max-width: 100% !important; border-radius: 0 !important; border-left: 0 !important; border-right: 0 !important; }
      .eml-pad { padding: 20px !important; }
      .eml-header-pad { padding: 28px 20px 20px 20px !important; }
      .eml-body-pad { padding: 24px 20px 28px 20px !important; }
      .eml-footer-pad { padding: 18px 20px !important; }
      .eml-col-50 { display: block !important; width: 100% !important; padding-right: 0 !important; }
      .eml-cta { padding: 12px 20px !important; }
      .eml-h1 { font-size: 20px !important; line-height: 1.25 !important; }
    }
    /* Dark-mode polish — keep legible text on Apple / Outlook dark modes. */
    @media (prefers-color-scheme: dark) {
      .eml-card-bg { background: #ffffff !important; }
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">

  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    ${escapeHtml(preheader)}
  </div>

  <!-- Wrapper Table -->
  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f9fafb; padding: 40px 16px;">
    <tr>
      <td align="center">

        <!-- Container Table -->
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" class="eml-container eml-card-bg" style="max-width: 600px; width: 100%; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">

          <!-- Top accent bar -->
          <tr>
            <td style="padding: 0; height: 6px; background: linear-gradient(90deg, #7c3aed 0%, #ec4899 50%, #f97316 100%);"></td>
          </tr>

          <!-- Header -->
          <tr>
            <td class="eml-header-pad" style="padding: 40px 48px 28px 48px; text-align: center; background-color: #ffffff; border-bottom: 1px solid #f1f5f9;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center">

                    ${logoBlock}

                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 0 auto 14px auto;">
                      <tr>
                        <td style="background: linear-gradient(135deg, #eff6ff, #f3e8ff); border: 1px solid #e0e7ff; border-radius: 24px; padding: 5px 16px;">
                          <span style="font-size: 11px; font-weight: 700; color: ${isApplicant ? '#7c3aed' : '#b45309'}; letter-spacing: 1px;">${headerChipLabel}</span>
                        </td>
                      </tr>
                    </table>

                    <h1 class="eml-h1" style="margin: 0; color: #0f172a; font-size: 24px; font-weight: 700; line-height: 1.3; letter-spacing: -0.3px;">
                      ${escapeHtml(jobTitle)}
                    </h1>
                    ${organizationName ? `<p style="margin: 6px 0 0 0; color: #64748b; font-size: 14px; line-height: 1.5;">${escapeHtml(organizationName)}</p>` : ''}
                    ${!isApplicant ? `<p style="margin: 4px 0 0 0; color: #64748b; font-size: 13px;">For candidate: <strong style="color:#0f172a;">${escapeHtml(candidateName)}</strong></p>` : ''}

                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content -->
          <tr>
            <td class="eml-body-pad" style="padding: 32px 48px 40px 48px; background-color: #fafbfc;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">

                ${greetingHtml}
                ${introHtml}

                ${roleBlock}
                ${startBlock}
                ${salaryBlock}
                ${benefitsBlock}
                ${descriptionBlock}
                ${contentBlock}
                ${messageBlock}
                ${fillBlock}
                ${contactBlock}

                ${closingHtml}

                ${acceptanceBlock}
                ${hrSignatureBlock}

                <!-- Help note -->
                <tr>
                  <td style="padding-top: 24px;">
                    <p style="margin: 0; color: #64748b; font-size: 13px; line-height: 1.6;">
                      Questions? Contact
                      <a href="mailto:${hrEmail}" style="color: #4f46e5; text-decoration: none; font-weight: 500;">${hrEmail}</a>.
                      ${isApplicant
                        ? 'If you did not apply for this position, please disregard this email.'
                        : 'If you received this email by mistake, please let the sender know and disregard it.'}
                    </p>
                  </td>
                </tr>

              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td class="eml-footer-pad" style="padding: 24px 48px; background: #ffffff; border-top: 1px solid #e5e7eb;">
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
                      &copy; 2026 ${escapeHtml(brandName)} &nbsp;·&nbsp;
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

    // ── Plain-text fallback — recipient-aware, same content split ───────────
    const textLines: string[] = [subject, ''];
    textLines.push(`Dear ${applicantName},`);
    textLines.push('');
    if (isApplicant) {
      textLines.push(
        `We are pleased to extend an offer for the position of ${jobTitle}${organizationName ? ` at ${organizationName}` : ''}.`,
      );
      textLines.push('');
      textLines.push('OFFER DETAILS');
      if (jobTitle)         textLines.push(`  Position:         ${jobTitle}`);
      if (employmentLabel)  textLines.push(`  Employment Type:  ${employmentLabel}`);
      if (jobLocation)      textLines.push(`  Location:         ${jobLocation}`);
      if (salary)           textLines.push(`  Annual Salary:    ${salary}`);
      if (startDate)        textLines.push(`  Start Date:       ${startDate}`);
      if (responseDeadline) textLines.push(`  Respond By:       ${responseDeadline}`);
      if (benefits?.trim())       textLines.push('', 'BENEFITS & PERKS',     benefits.trim());
      if (jobDescription?.trim()) textLines.push('', 'ABOUT THE ROLE',       truncate(jobDescription, 600));
      if (offerContent?.trim())   textLines.push('', 'OFFER LETTER',         offerContent.trim());
      if (message?.trim())        textLines.push('', 'A NOTE FROM THE TEAM', message.trim());
    } else {
      textLines.push(
        `You've been asked to review and sign the offer letter prepared for ${candidateName} for the role of ${jobTitle}${organizationName ? ` at ${organizationName}` : ''}.`,
      );
      textLines.push('');
      textLines.push('ROLE SUMMARY');
      if (jobTitle)        textLines.push(`  Position:         ${jobTitle}`);
      if (employmentLabel) textLines.push(`  Employment Type:  ${employmentLabel}`);
      if (jobLocation)     textLines.push(`  Location:         ${jobLocation}`);
      if (candidateName)   textLines.push(`  Candidate:        ${candidateName}`);
    }

    if (fillUrl) {
      const fillCopyText = buildFillCopy(recipientType, fillUrl);
      textLines.push(
        '',
        fillCopyText.heading.toUpperCase(),
        `  ${fillCopyText.body}`,
        `  ${fillCopyText.cta}: ${fillUrl}`,
        `  ${fillCopyText.footer}`,
      );
    }

    if (contactName || contactEmail || contactPhone) {
      textLines.push('', 'YOUR CONTACT');
      if (contactName)  textLines.push(`  ${contactName}`);
      if (contactEmail) textLines.push(`  ${contactEmail}`);
      if (contactPhone) textLines.push(`  ${contactPhone}`);
    }

    textLines.push('');
    if (isApplicant) {
      textLines.push(
        responseDeadline
          ? `Please respond to this offer by ${responseDeadline}.`
          : 'Please respond to this offer at your earliest convenience.',
      );
    } else {
      textLines.push(
        `Please open the document and sign it so HR can finalise ${candidateName}'s onboarding.`,
      );
    }
    textLines.push(
      'If you have any questions, simply reply to this email.',
      '',
      '---',
      brandName,
      'AI-Powered Healthcare Management Platform',
      `© 2026 ${brandName}. All rights reserved.`,
    );

    const text = textLines.filter((l) => l !== undefined && l !== null).join('\n');

    return { subject, html, text };
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

interface FillCopy {
  heading: string;
  body: string;
  cta: string;
  footer: string;
}

/**
 * Role-conditional copy for the email's CTA block. Each recipient type lands
 * somewhere different: supervisors in Document Workflow → Assignment tab,
 * employees on the Offer Letter tab of their Job view, external employees on
 * a token-gated public page, applicants on their own "My Applications" card.
 */
function buildFillCopy(
  recipientType: OfferRecipientKind | undefined,
  fillUrl: string | undefined,
): FillCopy {
  if (!fillUrl) {
    return { heading: '', body: '', cta: '', footer: '' };
  }
  switch (recipientType) {
    case 'supervisor':
      return {
        heading: 'Action required · Supervisor',
        body: 'An offer letter has been routed to you for review and sign-off. Open Document Workflow → Assignment tab to fill in your part of the document.',
        cta: 'Open Assignment Tab',
        footer: 'If the button does not work, copy and paste this URL into your browser:',
      };
    case 'employee':
      return {
        heading: 'Action required · Signer',
        body: 'Your signature is needed on an offer letter. Open your Jobs page and go to the Offer Letter tab to add your signature.',
        cta: 'Open Offer Letter',
        footer: 'If the button does not work, copy and paste this URL into your browser:',
      };
    case 'external_employee':
      return {
        heading: 'Action required · External signer',
        body: 'Please open the secure link below to sign this offer letter. The link is specific to you and can only be used during its validity period.',
        cta: 'Open Offer Letter',
        footer: 'If the button does not work, copy and paste this secure URL into your browser:',
      };
    case 'applicant':
      return {
        heading: 'Review and accept your offer',
        body: 'Your offer is ready. Open your applications page to review the full details and accept or decline the offer.',
        cta: 'Review My Offer',
        footer: 'If the button does not work, copy and paste this URL into your browser:',
      };
    default:
      return {
        heading: 'Action required · Signature',
        body: 'An offer letter is waiting for your signature. Use the link below to open the document.',
        cta: 'Open Offer Letter',
        footer: 'If the button does not work, copy and paste this URL into your browser:',
      };
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
