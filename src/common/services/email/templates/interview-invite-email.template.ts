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
  /** IANA timezone for the Add-to-Calendar deep links. */
  interviewTimezone?: string;
  interviewDurationMinutes?: number;
  /** Auto-generated video meeting URL (Zoom/Meet) — rendered separately from interviewLocation. */
  meetingLink?: string;
  /** Which platform created the link, for the "Join" button label. */
  meetingProvider?: 'zoom' | 'google_meet' | 'teams';
  /** Stable identifier used as the .ics UID so re-sends update the same event. */
  applicationId?: string;
  message?: string;
  jobLocation?: string;
  jobType?: string;
  salaryRange?: string;
  jobDescription?: string;
  organizationName?: string;
  contactName?: string;
  contactEmail?: string;
  contactPhone?: string;
  /**
   * Base URL of the employee portal's My Applications view.
   * When provided, the Confirm / Can't Attend buttons link here so the
   * candidate responds inside the app instead of via mailto.
   */
  confirmUrl?: string;
  declineUrl?: string;
  /** Pre-built "Add to Google Calendar" deep link. */
  googleCalendarLink?: string;
  /** Pre-built "Add to Outlook Calendar" deep link. */
  outlookCalendarLink?: string;
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
      meetingLink,
      meetingProvider,
      message,
      jobLocation,
      jobType,
      salaryRange,
      jobDescription,
      organizationName,
      contactName,
      contactEmail,
      contactPhone,
      confirmUrl,
      declineUrl,
      googleCalendarLink,
      outlookCalendarLink,
    } = opts;

    const brandName = organizationName?.trim() || 'homehealth.ai';
    const logoAlt = escapeHtml(brandName);

    const subject = organizationName
      ? `Interview Invitation – ${jobTitle} at ${organizationName}`
      : `Interview Invitation – ${jobTitle}`;

    const modeLabel = formatMode(interviewMode);
    const orgLine = organizationName
      ? `at <strong style="color:#0f172a;">${escapeHtml(organizationName)}</strong>`
      : '';
    const locationLabel =
      interviewMode === 'video'
        ? 'Meeting Link'
        : interviewMode === 'phone'
        ? 'Phone'
        : 'Location';
    const hrEmail = contactEmail ? escapeHtml(contactEmail) : 'hr@homehealth.ai';
    // const logoBlock = `<img src="cid:logo@homehealth.ai" alt="${logoAlt}" width="80" height="80" style="display: block; width: 80px; height: 80px; margin: 0 auto;" />`;

    // ── Interview Details rows ───────────────────────────────────────────────
    const effectiveLink =
      meetingLink ||
      (interviewMode === 'video' && interviewLocation && /^https?:\/\//i.test(interviewLocation)
        ? interviewLocation
        : undefined);
    const interviewRows: string[] = [];
    if (interviewDate)     interviewRows.push(tableRow('Date',     escapeHtml(interviewDate),     '#e5e7eb'));
    if (interviewTime)     interviewRows.push(tableRow('Time',     escapeHtml(interviewTime),     '#e5e7eb'));
    if (interviewDuration) interviewRows.push(tableRow('Duration', escapeHtml(interviewDuration), '#e5e7eb'));
    if (modeLabel)         interviewRows.push(tableRow('Format',   escapeHtml(modeLabel),         '#e5e7eb'));
    if (interviewLocation || effectiveLink) {
      const shown = effectiveLink ?? interviewLocation ?? '';
      const value =
        interviewMode === 'video' && /^https?:\/\//i.test(shown)
          ? `<a href="${escapeHtml(shown)}" style="color:#4f46e5;text-decoration:underline;font-weight:500;">${escapeHtml(shown)}</a>`
          : escapeHtml(shown);
      interviewRows.push(tableRow(locationLabel, value, '#e5e7eb'));
    }

    const interviewBlock = interviewRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('Interview Details', '#4f46e5', interviewRows.join(''))}</td></tr>`
      : '';

    // ── Join meeting + Add to Calendar block ─────────────────────────────────
    const joinLabel = meetingProvider === 'zoom'
      ? 'Join Zoom Meeting'
      : meetingProvider === 'google_meet'
        ? 'Join Google Meet'
        : meetingProvider === 'teams'
          ? 'Join Teams Meeting'
          : 'Join Meeting';
    const joinButton = effectiveLink
      ? `
                      <tr>
                        <td align="center" style="padding-bottom: 10px;">
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                              <td style="border-radius:6px;background:#4f46e5;">
                                <a href="${escapeHtml(effectiveLink)}" target="_blank"
                                   style="display:inline-block;padding:14px 32px;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;border-radius:6px;letter-spacing:0.2px;background:#4f46e5;">
                                  ▶ ${joinLabel}
                                </a>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>`
      : '';

    // Colored buttons render as buttons even in clients that strip CSS — the
    // bgcolor attribute is honoured by Outlook while `background` handles the
    // rest. Each link is its own <td> so they wrap on narrow mobile widths.
    const addCalendarButtons = (googleCalendarLink || outlookCalendarLink)
      ? `
                      <tr>
                        <td align="center" style="padding: 4px 0 6px 0;">
                          <p style="margin: 0 0 10px 0; font-size: 11px; font-weight: 700; color: #475569; letter-spacing: 0.8px; text-transform: uppercase;">📅 Add to Your Calendar</p>
                          <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                              ${googleCalendarLink ? `<td style="padding:4px 4px;" bgcolor="#1a73e8">
                                <a href="${escapeHtml(googleCalendarLink)}" target="_blank"
                                   style="display:inline-block;padding:11px 18px;color:#ffffff;font-size:13px;font-weight:600;text-decoration:none;border-radius:6px;background:#1a73e8;">
                                  Google Calendar
                                </a></td>` : ''}
                              ${outlookCalendarLink ? `<td style="padding:4px 4px;" bgcolor="#0078d4">
                                <a href="${escapeHtml(outlookCalendarLink)}" target="_blank"
                                   style="display:inline-block;padding:11px 18px;color:#ffffff;font-size:13px;font-weight:600;text-decoration:none;border-radius:6px;background:#0078d4;">
                                  Outlook Calendar
                                </a></td>` : ''}
                            </tr>
                          </table>
                          <p style="margin: 12px 0 0 0; color:#64748b; font-size:12px; line-height:1.5;">
                            Using <strong>Apple Calendar</strong>, <strong>iPhone</strong>, or another client?
                            <br>Open the attached <strong>invite.ics</strong> file to add this interview to your calendar.
                          </p>
                        </td>
                      </tr>`
      : '';

    // Wrap the calendar block in a lightly tinted card so it reads as a
    // distinct CTA section and doesn't blend into the surrounding body copy.
    const calendarCard = addCalendarButtons
      ? `<tr>
          <td style="padding: 4px 0 16px 0;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;">
              <tr><td style="padding: 18px 16px;">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">${addCalendarButtons}</table>
              </td></tr>
            </table>
          </td>
        </tr>`
      : '';
    const joinAndCalendarBlock = (joinButton || addCalendarButtons)
      ? `<tr><td style="padding: 4px 0 8px 0;"><table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">${joinButton}</table></td></tr>${calendarCard}`
      : '';

    // ── About the Role rows ──────────────────────────────────────────────────
    const roleRows: string[] = [];
    if (jobTitle)    roleRows.push(tableRow('Position',     escapeHtml(jobTitle),    '#e5e7eb'));
    if (jobType)     roleRows.push(tableRow('Job Type',     escapeHtml(jobType),     '#e5e7eb'));
    if (jobLocation) roleRows.push(tableRow('Location',     escapeHtml(jobLocation), '#e5e7eb'));
    if (salaryRange) roleRows.push(tableRow('Salary Range', escapeHtml(salaryRange), '#e5e7eb'));

    const roleBlock = roleRows.length
      ? `<tr><td style="padding-bottom:16px;">${sectionCard('About the Role', '#059669', roleRows.join(''))}</td></tr>`
      : '';

    // ── Job description block ────────────────────────────────────────────────
    const descriptionBlock = jobDescription?.trim()
      ? `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('Job Summary', '#475569', `<tr><td style="color:#374151;font-size:14px;line-height:1.7;white-space:pre-wrap;">${escapeHtml(truncate(jobDescription, 600))}</td></tr>`)}
                  </td>
                </tr>`
      : '';

    // ── What to Prepare block ────────────────────────────────────────────────
    const prepareBlock = `
                <tr>
                  <td style="padding-bottom: 16px;">
                    ${sectionCard('What to Prepare', '#d97706', prepareRows())}
                  </td>
                </tr>`;

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

    // ── Full HTML ────────────────────────────────────────────────────────────
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Interview Invitation – ${escapeHtml(jobTitle)} – ${escapeHtml(brandName)}</title>
  <!--[if mso]>
  <style type="text/css">
    body, table, td {font-family: Arial, sans-serif !important;}
  </style>
  <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">

  <!-- Preheader Text (Hidden) -->
  <div style="display: none; max-height: 0; overflow: hidden;">
    You have been invited to interview for ${escapeHtml(jobTitle)}${organizationName ? ` at ${escapeHtml(organizationName)}` : ''} – ${escapeHtml(brandName)}.
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
                    <img src="cid:logo@homehealth.ai" alt="HomeHealth.AI" width="80" height="80" style="display: block; width: 80px; height: 80px;" />
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: 0 auto 14px auto;">
                      <tr>
                        <td style="background: linear-gradient(135deg, #eff6ff, #f3e8ff); border: 1px solid #e0e7ff; border-radius: 24px; padding: 5px 16px;">
                          <span style="font-size: 11px; font-weight: 700; color: #7c3aed; letter-spacing: 1px;">INTERVIEW INVITATION</span>
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
                      Thank you for applying for the position of
                      <strong style="color: #0f172a;">${escapeHtml(jobTitle)}</strong> ${orgLine}.
                      Following our review of your application, we would like to invite you to an interview. Details are outlined below.
                    </p>
                  </td>
                </tr>

                ${interviewBlock}
                ${joinAndCalendarBlock}
                ${roleBlock}
                ${descriptionBlock}
                ${prepareBlock}
                ${messageBlock}
                ${contactBlock}

                <!-- Reschedule note -->
                <tr>
                  <td style="padding: 8px 0 24px 0;">
                    <p style="margin: 0; color: #374151; font-size: 14px; line-height: 1.7;">
                      <strong style="color: #0f172a;">Need to reschedule?</strong>
                      Reply to this email or contact
                      <a href="mailto:${hrEmail}" style="color: #4f46e5; text-decoration: none; font-weight: 500;">${hrEmail}</a>
                      at least 24 hours before your scheduled time.
                    </p>
                  </td>
                </tr>

                <!-- Response CTAs — confirm / can't attend -->
                <tr>
                  <td align="center" style="padding: 4px 0 8px 0;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td style="border-radius: 6px; background: #16a34a; padding-right: 10px;">
                          <a href="${escapeHtml(
                            confirmUrl ||
                              `mailto:${hrEmail}?subject=Interview%20Confirmation%20%E2%80%93%20${encodeURIComponent(jobTitle)}`,
                          )}"
                             target="_blank"
                             style="display: inline-block; padding: 14px 28px; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 6px; letter-spacing: 0.2px; background: #16a34a;">
                            ✓ Confirm Attendance
                          </a>
                        </td>
                        <td style="width: 12px;">&nbsp;</td>
                        <td style="border-radius: 6px; background: #ffffff; border: 1px solid #fca5a5;">
                          <a href="${escapeHtml(
                            declineUrl ||
                              `mailto:${hrEmail}?subject=Interview%20%E2%80%93%20Can%27t%20Attend%20%E2%80%93%20${encodeURIComponent(jobTitle)}&body=${encodeURIComponent(
                                'Hello,\n\nUnfortunately I am not available at the scheduled time. My availability is:\n\n',
                              )}`,
                          )}"
                             target="_blank"
                             style="display: inline-block; padding: 13px 28px; color: #b91c1c; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 6px; letter-spacing: 0.2px;">
                            ✗ I can't make it
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding: 6px 0 8px 0;">
                    <p style="margin: 0; color: #6b7280; font-size: 12px;">
                      ${confirmUrl
                        ? "You'll be taken to your applications page to confirm."
                        : 'Click a button above to reply by email.'}
                    </p>
                  </td>
                </tr>

                <!-- Help note -->
                <tr>
                  <td style="padding-top: 28px; border-top: 1px solid #e5e7eb; margin-top: 28px;">
                    <p style="margin: 0; color: #64748b; font-size: 13px; line-height: 1.6;">
                      If you did not apply for this role, please disregard this email.
                      Questions? Contact
                      <a href="mailto:${hrEmail}" style="color: #4f46e5; text-decoration: none; font-weight: 500;">${hrEmail}</a>.
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

    // ── Plain-text fallback ──────────────────────────────────────────────────
    const textLines = [
      subject,
      '',
      `Dear ${applicantName},`,
      '',
      `Thank you for applying for the position of ${jobTitle}${organizationName ? ` at ${organizationName}` : ''}. We have scheduled your interview as follows:`,
      '',
      'INTERVIEW DETAILS',
      interviewDate     ? `  Date:     ${interviewDate}`     : '',
      interviewTime     ? `  Time:     ${interviewTime}`     : '',
      interviewDuration ? `  Duration: ${interviewDuration}` : '',
      modeLabel         ? `  Format:   ${modeLabel}`         : '',
      effectiveLink
        ? `  ${locationLabel}: ${effectiveLink}`
        : interviewLocation
          ? `  ${locationLabel}: ${interviewLocation}`
          : '',
    ];

    if (googleCalendarLink || outlookCalendarLink) {
      textLines.push('', 'ADD TO CALENDAR');
      if (googleCalendarLink)  textLines.push(`  Google:  ${googleCalendarLink}`);
      if (outlookCalendarLink) textLines.push(`  Outlook: ${outlookCalendarLink}`);
      textLines.push('  Apple: open the attached invite.ics');
    }

    if (jobTitle || jobType || jobLocation || salaryRange) {
      textLines.push('', 'ABOUT THE ROLE');
      if (jobTitle)    textLines.push(`  Position:     ${jobTitle}`);
      if (jobType)     textLines.push(`  Job Type:     ${jobType}`);
      if (jobLocation) textLines.push(`  Location:     ${jobLocation}`);
      if (salaryRange) textLines.push(`  Salary Range: ${salaryRange}`);
    }
    if (jobDescription?.trim()) textLines.push('', 'JOB SUMMARY',          truncate(jobDescription, 600));
    if (message?.trim())        textLines.push('', 'A NOTE FROM THE TEAM', message.trim());

    if (contactName || contactEmail || contactPhone) {
      textLines.push('', 'YOUR CONTACT');
      if (contactName)  textLines.push(`  ${contactName}`);
      if (contactEmail) textLines.push(`  ${contactEmail}`);
      if (contactPhone) textLines.push(`  ${contactPhone}`);
    }

    textLines.push(
      '',
      'Please reply to this email to confirm your attendance or to reschedule.',
      'We look forward to speaking with you.',
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

/**
 * Renders a two-column label/value table row — identical to offer letter helper.
 */
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

/**
 * Renders a colour-coded info card — identical to offer letter helper.
 */
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

/**
 * Returns the 4 numbered preparation tips as table rows — identical to offer letter helper.
 */
function prepareRows(): string {
  const tips = [
    'An updated copy of your resume / CV',
    'Portfolio or relevant work samples (if applicable)',
    'A stable internet connection &amp; working camera (for video interviews)',
    'Questions you&#39;d like to ask about the role or team',
  ];
  return tips
    .map(
      (tip) => `
                  <tr>
                    <td style="padding: 4px 0; vertical-align: top;">
                      <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                        <tr>
                          <td valign="top" style="width: 16px; padding-right: 10px; color: #d97706; font-size: 13px; font-weight: 700; line-height: 1.6;">&#10003;</td>
                          <td style="color: #374151; font-size: 13px; line-height: 1.6;">${tip}</td>
                        </tr>
                      </table>
                    </td>
                  </tr>`,
    )
    .join('');
}

function formatMode(mode?: string): string {
  if (!mode) return '';
  switch (mode) {
    case 'in_person': return 'In-person';
    case 'video':     return 'Video call';
    case 'phone':     return 'Phone';
    default:          return mode.replace(/_/g, ' ');
  }
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