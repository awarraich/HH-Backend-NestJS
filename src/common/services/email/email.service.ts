import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as fs from 'fs';
import * as path from 'path';
import { EmailConfigService } from '../../../config/email/config.service';
import { VerificationEmailTemplate } from './templates/verification-email.template';
import { PasswordResetEmailTemplate } from './templates/password-reset-email.template';
import { AdminCreatedUserEmailTemplate } from './templates/admin-created-user-email.template';
import { AdminUpdatedUserEmailTemplate } from './templates/admin-updated-user-email.template';
import { OrganizationStaffCreatedEmailTemplate } from './templates/organization-staff-created-email.template';
import { GoogleSignInInviteEmailTemplate } from './templates/google-sign-in-invite-email.template';
import { InterviewInviteEmailTemplate } from './templates/interview-invite-email.template';
import { OfferLetterEmailTemplate } from './templates/offer-letter-email.template';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;
  private logoBuffer: Buffer | null = null;

  constructor(private emailConfigService: EmailConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.emailConfigService.host,
      port: this.emailConfigService.port,
      secure: this.emailConfigService.secure,
      auth: this.emailConfigService.auth,
    });
    this.loadLogo();
  }

  private loadLogo(): void {
    try {
      const logoPath = path.join(process.cwd(), 'src', 'common', 'services', 'email', 'assets', 'logo-email.png');
      this.logoBuffer = fs.readFileSync(logoPath);
    } catch {
      this.logger.warn('Could not load email logo from src/. Emails will be sent without logo.');
    }
  }

  private get logoAttachment(): nodemailer.SendMailOptions['attachments'] {
    if (!this.logoBuffer) return [];
    return [
      {
        filename: 'logo.png',
        content: this.logoBuffer,
        contentType: 'image/png',
        cid: 'logo@homehealth.ai',
      },
    ];
  }

  /**
   * Build a logo attachment for a specific organization. When the org has its
   * own logo uploaded, that image is attached inline under the same CID
   * (`logo@homehealth.ai`) the templates reference, so the per-org image
   * replaces the default without template changes. Falls back to the default
   * homehealth logo otherwise. Inline attachment is used (rather than a URL)
   * so the image renders reliably in Gmail/Outlook regardless of whether the
   * backend is publicly reachable.
   */
  private buildLogoAttachment(
    orgLogo?: { buffer: Buffer; contentType: string; file_name?: string } | null,
  ): nodemailer.SendMailOptions['attachments'] {
    if (orgLogo) {
      return [
        {
          filename: orgLogo.file_name ?? 'logo',
          content: orgLogo.buffer,
          contentType: orgLogo.contentType || 'application/octet-stream',
          cid: 'logo@homehealth.ai',
        },
      ];
    }
    return this.logoAttachment;
  }

  async onModuleInit(): Promise<void> {
    await this.verifyConnection();
  }

  /**
   * Verify SMTP connection on startup
   */
  private async verifyConnection(): Promise<void> {
    try {
      const auth = this.emailConfigService.auth;

      // Check if credentials are provided
      if (!auth.user || !auth.pass) {
        this.logger.warn(
          'Email credentials not configured. Email sending will fail. ' +
            'Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
        return;
      }

      // Verify connection
      await this.transporter.verify();
      this.logger.log(
        `SMTP connection verified successfully. Host: ${this.emailConfigService.host}:${this.emailConfigService.port}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to verify SMTP connection. Email sending may fail. ` +
          `Please check your EMAIL_HOST, EMAIL_PORT, EMAIL_USER, and EMAIL_PASSWORD configuration.`,
        error instanceof Error ? error.stack : String(error),
      );
    }
  }

  async sendVerificationEmail(
    email: string,
    token: string,
    userName: string,
    userEmail: string,
  ): Promise<void> {
    try {
      // Validate email configuration
      const auth = this.emailConfigService.auth;
      if (!auth.user || !auth.pass) {
        throw new Error(
          'Email service not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
      }

      const template = VerificationEmailTemplate.generate(
        this.emailConfigService.verificationUrl,
        token,
        userName,
        userEmail,
      );

      const mailOptions = {
        from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
        attachments: this.logoAttachment,
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Verification email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send verification email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send verification email: ${errorMessage}. Please check your email configuration.`,
      );
    }
  }

  async sendPasswordResetEmail(
    email: string,
    token: string,
    userName: string,
    userEmail: string,
  ): Promise<void> {
    try {
      // Validate email configuration
      const auth = this.emailConfigService.auth;
      if (!auth.user || !auth.pass) {
        throw new Error(
          'Email service not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
      }

      const template = PasswordResetEmailTemplate.generate(
        this.emailConfigService.passwordResetUrl,
        token,
        userName,
        userEmail,
      );

      const mailOptions = {
        from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
        attachments: this.logoAttachment,
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Password reset email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send password reset email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send password reset email: ${errorMessage}. Please check your email configuration.`,
      );
    }
  }

  async sendAdminCreatedUserEmail(
    email: string,
    password: string,
    token: string,
    userName: string,
    userEmail: string,
    loginUrl: string,
  ): Promise<void> {
    try {
      // Validate email configuration
      const auth = this.emailConfigService.auth;
      if (!auth.user || !auth.pass) {
        throw new Error(
          'Email service not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
      }

      const template = AdminCreatedUserEmailTemplate.generate(
        this.emailConfigService.verificationUrl,
        token,
        userName,
        userEmail,
        password,
        loginUrl,
      );

      const mailOptions = {
        from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
        attachments: this.logoAttachment,
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Admin-created user email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send admin-created user email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send admin-created user email: ${errorMessage}. Please check your email configuration.`,
      );
    }
  }

  async sendOrganizationStaffCreatedEmail(
    email: string,
    userName: string,
    userEmail: string,
    temporaryPassword: string,
    loginUrl: string,
    expiresInHours: number = 24,
  ): Promise<void> {
    try {
      const auth = this.emailConfigService.auth;
      if (!auth.user || !auth.pass) {
        throw new Error(
          'Email service not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
      }

      const template = OrganizationStaffCreatedEmailTemplate.generate(
        userName,
        userEmail,
        temporaryPassword,
        loginUrl,
        expiresInHours,
      );

      const mailOptions = {
        from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
        attachments: this.logoAttachment,
      };

      await this.transporter.sendMail(mailOptions);

      this.logger.log(`Organization staff created email sent to: ${this.maskEmail(email)}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send organization staff created email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send organization staff created email: ${errorMessage}. Please check your email configuration.`,
      );
    }
  }

  async sendGoogleSignInInviteEmail(
    email: string,
    name: string,
    loginUrl: string,
    organizationName: string,
  ): Promise<void> {
    try {
      const auth = this.emailConfigService.auth;
      if (!auth.user || !auth.pass) {
        throw new Error(
          'Email service not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
      }

      const template = GoogleSignInInviteEmailTemplate.generate(
        name,
        email,
        loginUrl,
        organizationName,
      );

      const mailOptions = {
        from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
        attachments: this.logoAttachment,
      };

      await this.transporter.sendMail(mailOptions);

      this.logger.log(`Google sign-in invite email sent to: ${this.maskEmail(email)}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send Google sign-in invite email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send Google sign-in invite email: ${errorMessage}. Please check your email configuration.`,
      );
    }
  }

  async sendAdminUpdatedUserEmail(
    email: string,
    userName: string,
    userEmail: string,
    changes: {
      password?: boolean;
      email?: { old: string; new: string };
      firstName?: { old: string; new: string };
      lastName?: { old: string; new: string };
      role?: { old: string; new: string };
    },
    loginUrl: string,
  ): Promise<void> {
    try {
      // Validate email configuration
      const auth = this.emailConfigService.auth;
      if (!auth.user || !auth.pass) {
        throw new Error(
          'Email service not configured. Please set EMAIL_USER and EMAIL_PASSWORD environment variables.',
        );
      }

      const template = AdminUpdatedUserEmailTemplate.generate(
        userName,
        userEmail,
        changes,
        loginUrl,
      );

      const mailOptions = {
        from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
        to: email,
        subject: template.subject,
        html: template.html,
        text: template.text,
        attachments: this.logoAttachment,
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Admin-updated user email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send admin-updated user email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send admin-updated user email: ${errorMessage}. Please check your email configuration.`,
      );
    }
  }

  /**
   * Send interview invite email to applicant (Schedule Interview modal content).
   * Used when org clicks "Schedule Interview" on job applications page.
   * Pass `orgLogo` to override the default logo with the organization's own
   * uploaded logo (sent as an inline CID attachment).
   */
  async sendInterviewInviteEmail(
    toEmail: string,
    options: Omit<
      Parameters<typeof InterviewInviteEmailTemplate.generate>[0],
      never
    >,
    orgLogo?: { buffer: Buffer; contentType: string; file_name?: string } | null,
  ): Promise<void> {
    const auth = this.emailConfigService.auth;
    if (!auth.user || !auth.pass) {
      throw new Error(
        'Email service not configured. Set EMAIL_USER and EMAIL_PASSWORD (e.g. in production) to send interview invites.',
      );
    }
    const template = InterviewInviteEmailTemplate.generate(options);
    const mailOptions = {
      from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
      to: toEmail,
      subject: template.subject,
      html: template.html,
      text: template.text,
      attachments: this.buildLogoAttachment(orgLogo),
    };
    const info = await this.transporter.sendMail(mailOptions);
    this.logger.log(
      `Interview invite email sent to: ${this.maskEmail(toEmail)}. MessageId: ${info.messageId}`,
    );
  }

  /**
   * Send offer letter email to applicant (Send Offer modal content).
   * Used when org clicks "Send Offer" on job applications page.
   * Pass `orgLogo` to override the default logo with the organization's own
   * uploaded logo (sent as an inline CID attachment).
   */
  async sendOfferLetterEmail(
    toEmail: string,
    options: Omit<
      Parameters<typeof OfferLetterEmailTemplate.generate>[0],
      never
    >,
    orgLogo?: { buffer: Buffer; contentType: string; file_name?: string } | null,
  ): Promise<void> {
    const auth = this.emailConfigService.auth;
    if (!auth.user || !auth.pass) {
      throw new Error(
        'Email service not configured. Set EMAIL_USER and EMAIL_PASSWORD (e.g. in production) to send offer letters.',
      );
    }
    const template = OfferLetterEmailTemplate.generate(options);
    const mailOptions = {
      from: `"${this.emailConfigService.fromName}" <${this.emailConfigService.from}>`,
      to: toEmail,
      subject: template.subject,
      html: template.html,
      text: template.text,
      attachments: this.buildLogoAttachment(orgLogo),
    };
    const info = await this.transporter.sendMail(mailOptions);
    this.logger.log(
      `Offer letter email sent to: ${this.maskEmail(toEmail)}. MessageId: ${info.messageId}`,
    );
  }

  private maskEmail(email: string): string {
    // HIPAA Compliance: Mask email in logs
    const [localPart, domain] = email.split('@');
    if (!domain) return email;
    const maskedLocal =
      localPart.length > 2
        ? `${localPart[0]}${'*'.repeat(localPart.length - 2)}${localPart[localPart.length - 1]}`
        : '**';
    return `${maskedLocal}@${domain}`;
  }
}
