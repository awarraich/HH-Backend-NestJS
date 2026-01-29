import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import axios from 'axios';
import { RecaptchaConfigService } from '../../../config/recaptcha/config.service';

interface RecaptchaVerifyResponse {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  'error-codes'?: string[];
}

@Injectable()
export class RecaptchaService {
  private readonly logger = new Logger(RecaptchaService.name);

  constructor(private recaptchaConfigService: RecaptchaConfigService) {}

  /**
   * Verify reCAPTCHA token
   */
  async verifyToken(token: string, remoteip?: string): Promise<boolean> {
    // If reCAPTCHA is disabled, skip verification
    if (!this.recaptchaConfigService.enabled) {
      this.logger.debug('reCAPTCHA is disabled, skipping verification');
      return true;
    }

    if (!token) {
      throw new BadRequestException('reCAPTCHA token is required');
    }

    const secretKey = this.recaptchaConfigService.secretKey;
    if (!secretKey) {
      this.logger.warn('reCAPTCHA secret key not configured');
      throw new BadRequestException('reCAPTCHA is not properly configured');
    }

    try {
      const verifyUrl = this.recaptchaConfigService.verifyUrl;
      const params = new URLSearchParams({
        secret: secretKey,
        response: token,
        ...(remoteip && { remoteip }),
      });

      const response = await axios.post<RecaptchaVerifyResponse>(
        verifyUrl,
        params.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          timeout: 5000, // 5 second timeout
        },
      );

      if (!response.data.success) {
        const errorCodes = response.data['error-codes'] || [];
        this.logger.warn(
          `reCAPTCHA verification failed. Error codes: ${errorCodes.join(', ')}`,
        );
        return false;
      }

      this.logger.debug('reCAPTCHA verification successful');
      return true;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to verify reCAPTCHA token: ${errorMessage}`);
      throw new BadRequestException('Failed to verify reCAPTCHA token');
    }
  }

  /**
   * Get reCAPTCHA site key (for frontend)
   */
  getSiteKey(): string {
    return this.recaptchaConfigService.siteKey;
  }

  /**
   * Check if reCAPTCHA is enabled
   */
  isEnabled(): boolean {
    return this.recaptchaConfigService.enabled;
  }
}

