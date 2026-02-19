import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { EmailConfigService } from '../../../config/email/config.service';
import { VerificationEmailTemplate } from './templates/verification-email.template';
import { PasswordResetEmailTemplate } from './templates/password-reset-email.template';
import { AdminCreatedUserEmailTemplate } from './templates/admin-created-user-email.template';
import { AdminUpdatedUserEmailTemplate } from './templates/admin-updated-user-email.template';
import { OrganizationStaffCreatedEmailTemplate } from './templates/organization-staff-created-email.template';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private emailConfigService: EmailConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.emailConfigService.host,
      port: this.emailConfigService.port,
      secure: this.emailConfigService.secure,
      auth: this.emailConfigService.auth,
    });
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
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Verification email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
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
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Password reset email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
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
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Admin-created user email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
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
      };

      await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Organization staff created email sent to: ${this.maskEmail(email)}`,
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send organization staff created email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send organization staff created email: ${errorMessage}. Please check your email configuration.`,
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
      };

      const info = await this.transporter.sendMail(mailOptions);

      this.logger.log(
        `Admin-updated user email sent to: ${this.maskEmail(email)}. MessageId: ${info.messageId}`,
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to send admin-updated user email to: ${this.maskEmail(email)}. Error: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(
        `Failed to send admin-updated user email: ${errorMessage}. Please check your email configuration.`,
      );
    }
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
