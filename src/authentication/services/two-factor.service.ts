import { Injectable, Logger } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as CryptoJS from 'crypto-js';
import { ConfigService } from '@nestjs/config';
import { TotpSecretInterface } from '../interfaces/totp-secret.interface';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);
  private readonly encryptionKey: string;

  constructor(private configService: ConfigService) {
    this.encryptionKey =
      this.configService.get<string>('TOTP_ENCRYPTION_KEY') ||
      'default-encryption-key-change-in-production';
  }

  /**
   * Generate a new TOTP secret for a user
   * @param email - User's email for the secret label
   * @returns TOTP secret with QR code URL and manual entry key
   */
  async generateSecret(email: string): Promise<TotpSecretInterface> {
    const secret = speakeasy.generateSecret({
      name: `Home Health AI (${email})`,
      issuer: 'Home Health AI',
      length: 32,
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url || '');

    return {
      secret: secret.base32 || '',
      qrCodeUrl,
      manualEntryKey: secret.base32 || '',
    };
  }

  /**
   * Verify a TOTP token
   * @param token - The 6-digit TOTP token
   * @param secret - The encrypted TOTP secret
   * @returns true if token is valid
   */
  verifyToken(token: string, encryptedSecret: string): boolean {
    try {
      // Decrypt the secret
      const decryptedSecret = this.decryptSecret(encryptedSecret);

      // Verify the token
      const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: 'base32',
        token,
        window: 2, // Allow 2 time steps (60 seconds) of tolerance
      });

      return verified === true;
    } catch (error) {
      this.logger.error('Error verifying TOTP token', error);
      return false;
    }
  }

  /**
   * Encrypt TOTP secret for storage
   * @param secret - Plain text secret
   * @returns Encrypted secret
   */
  encryptSecret(secret: string): string {
    return CryptoJS.AES.encrypt(secret, this.encryptionKey).toString();
  }

  /**
   * Decrypt TOTP secret from storage
   * @param encryptedSecret - Encrypted secret
   * @returns Plain text secret
   */
  decryptSecret(encryptedSecret: string): string {
    const bytes = CryptoJS.AES.decrypt(encryptedSecret, this.encryptionKey);
    return bytes.toString(CryptoJS.enc.Utf8);
  }

  /**
   * Generate a TOTP token for testing (should not be used in production)
   * @param secret - The encrypted TOTP secret
   * @returns 6-digit token
   */
  generateToken(encryptedSecret: string): string {
    try {
      const decryptedSecret = this.decryptSecret(encryptedSecret);
      return speakeasy.totp({
        secret: decryptedSecret,
        encoding: 'base32',
      });
    } catch (error) {
      this.logger.error('Error generating TOTP token', error);
      throw error;
    }
  }
}
