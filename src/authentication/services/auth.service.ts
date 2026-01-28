import {
  Injectable,
  Logger,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { UserRepository } from '../repositories/user.repository';
import { RoleRepository } from '../repositories/role.repository';
import { User } from '../entities/user.entity';
import { EmailService } from '../../common/services/email/email.service';
import { TwoFactorService } from './two-factor.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyEmailDto } from '../dto/verify-email.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { Verify2FADto } from '../dto/verify-2fa.dto';
import { AuthResponseInterface } from '../interfaces/auth-response.interface';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { DataSource } from 'typeorm';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private userRepository: UserRepository,
    private roleRepository: RoleRepository,
    private jwtService: JwtService,
    private emailService: EmailService,
    private twoFactorService: TwoFactorService,
    private configService: ConfigService,
    private dataSource: DataSource,
  ) {}

  /**
   * Register a new user with email verification
   */
  async register(registerDto: RegisterDto): Promise<{ message: string }> {
    // Check if user already exists
    const existingUser = await this.userRepository.findByEmail(registerDto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create user
    const user = this.userRepository.create({
      firstName: registerDto.firstName,
      lastName: registerDto.lastName,
      email: registerDto.email,
      password: hashedPassword,
      email_verification_token: verificationToken,
      email_verification_sent_at: new Date(),
      email_verified: false,
      is_active: true,
    });

    await this.userRepository.save(user);

    // Send verification email
    try {
      await this.emailService.sendVerificationEmail(registerDto.email, verificationToken);
    } catch (error) {
      this.logger.error('Failed to send verification email', error);
      // Don't throw - user is created, they can request resend
    }

    this.logger.log(`User registered: ${this.maskEmail(registerDto.email)}`);

    return {
      message: 'Registration successful. Please check your email to verify your account.',
    };
  }

  /**
   * Login user with optional 2FA
   */
  async login(loginDto: LoginDto, twoFactorToken?: string): Promise<AuthResponseInterface> {
    // Find user with password
    const user = await this.userRepository.findByEmailWithPassword(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);

    if (!isPasswordValid) {
      this.logger.warn(`Failed login attempt for: ${this.maskEmail(loginDto.email)}`);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user is active
    if (!user.is_active) {
      throw new UnauthorizedException('Account is inactive');
    }

    // Check if email is verified
    if (!user.email_verified) {
      throw new UnauthorizedException('Please verify your email before logging in');
    }

    // Check if 2FA is enabled
    if (user.is_two_fa_enabled) {
      if (!twoFactorToken) {
        // Return that 2FA is required
        return {
          accessToken: '',
          refreshToken: '',
          user: {
            id: user.id,
            email: user.email,
            emailVerified: user.email_verified,
            isTwoFaEnabled: true,
            roles: [],
          },
          requiresTwoFactor: true,
        };
      }

      // Verify 2FA token
      if (!user.totp_secret) {
        throw new BadRequestException('2FA is enabled but secret is missing');
      }

      const isValid2FA = this.twoFactorService.verifyToken(twoFactorToken, user.totp_secret);

      if (!isValid2FA) {
        throw new UnauthorizedException('Invalid 2FA token');
      }

      // Update last 2FA verification time
      user.last_2fa_verified_at = new Date();
    }

    // Update last login
    user.last_login = new Date();
    await this.userRepository.save(user);

    // Get user roles
    const userWithRoles = await this.userRepository.findByIdWithRoles(user.id);
    const roles = userWithRoles?.userRoles?.map((ur) => ur.role.name) || [];

    // Generate tokens
    const tokens = await this.generateTokens(user, roles);

    this.logger.log(`User logged in: ${this.maskEmail(user.email)}`);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified,
        isTwoFaEnabled: user.is_two_fa_enabled,
        roles,
      },
    };
  }

  /**
   * Verify email with token
   */
  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<{
    message: string;
  }> {
    const user = await this.userRepository.findByVerificationToken(verifyEmailDto.token);

    if (!user) {
      throw new NotFoundException('Invalid or expired verification token');
    }

    // Check if token is expired (24 hours)
    if (!user.email_verification_sent_at) {
      throw new BadRequestException('Verification token has expired');
    }
    const tokenAge = Date.now() - new Date(user.email_verification_sent_at).getTime();
    const twentyFourHours = 24 * 60 * 60 * 1000;

    if (tokenAge > twentyFourHours) {
      throw new BadRequestException('Verification token has expired');
    }

    // Verify email
    user.email_verified = true;
    user.email_verification_token = null;
    user.email_verification_sent_at = null;

    await this.userRepository.save(user);

    this.logger.log(`Email verified for: ${this.maskEmail(user.email)}`);

    return { message: 'Email verified successfully' };
  }

  /**
   * Resend verification email
   */
  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      // Don't reveal if user exists
      return {
        message: 'If an account exists with this email, a verification email has been sent.',
      };
    }

    if (user.email_verified) {
      throw new BadRequestException('Email is already verified');
    }

    // Generate new token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.email_verification_token = verificationToken;
    user.email_verification_sent_at = new Date();

    await this.userRepository.save(user);

    // Send email
    try {
      await this.emailService.sendVerificationEmail(email, verificationToken);
    } catch (error) {
      this.logger.error('Failed to send verification email', error);
      throw new BadRequestException('Failed to send verification email');
    }

    return {
      message: 'Verification email sent successfully',
    };
  }

  /**
   * Request password reset
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<{ message: string }> {
    const user = await this.userRepository.findByEmail(forgotPasswordDto.email);

    if (!user) {
      // Don't reveal if user exists
      return {
        message: 'If an account exists with this email, a password reset email has been sent.',
      };
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.password_reset_token = resetToken;
    user.password_reset_sent_at = new Date();

    await this.userRepository.save(user);

    // Send email
    try {
      await this.emailService.sendPasswordResetEmail(forgotPasswordDto.email, resetToken);
    } catch (error) {
      this.logger.error('Failed to send password reset email', error);
      throw new BadRequestException('Failed to send password reset email');
    }

    this.logger.log(`Password reset requested for: ${this.maskEmail(forgotPasswordDto.email)}`);

    return {
      message: 'If an account exists with this email, a password reset email has been sent.',
    };
  }

  /**
   * Reset password with token
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    const user = await this.userRepository.findByPasswordResetToken(resetPasswordDto.token);

    if (!user) {
      throw new NotFoundException('Invalid or expired reset token');
    }

    // Check if token is expired (1 hour)
    if (!user.password_reset_sent_at) {
      throw new BadRequestException('Reset token has expired');
    }
    const tokenAge = Date.now() - new Date(user.password_reset_sent_at).getTime();
    const oneHour = 60 * 60 * 1000;

    if (tokenAge > oneHour) {
      throw new BadRequestException('Reset token has expired');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(resetPasswordDto.newPassword, 10);

    // Update password and clear reset token
    user.password = hashedPassword;
    user.password_reset_token = null;
    user.password_reset_sent_at = null;

    await this.userRepository.save(user);

    this.logger.log(`Password reset for: ${this.maskEmail(user.email)}`);

    return { message: 'Password reset successfully' };
  }

  /**
   * Enable 2FA for user
   */
  async enable2FA(userId: string): Promise<{
    secret: string;
    qrCodeUrl: string;
    manualEntryKey: string;
  }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.is_two_fa_enabled) {
      throw new BadRequestException('2FA is already enabled');
    }

    // Generate secret
    const secretData = await this.twoFactorService.generateSecret(user.email);

    // Encrypt and store secret (but don't enable yet - user needs to verify first)
    const encryptedSecret = this.twoFactorService.encryptSecret(secretData.secret);
    user.totp_secret = encryptedSecret;
    user.totp_secret_created_at = new Date();

    await this.userRepository.save(user);

    return {
      secret: secretData.secret, // Return plain secret for QR code generation
      qrCodeUrl: secretData.qrCodeUrl,
      manualEntryKey: secretData.manualEntryKey,
    };
  }

  /**
   * Verify and enable 2FA
   */
  async verify2FASetup(userId: string, verify2FADto: Verify2FADto): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'totp_secret', 'is_two_fa_enabled'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.totp_secret) {
      throw new BadRequestException('2FA secret not found. Please enable 2FA first.');
    }

    // Verify token
    const isValid = this.twoFactorService.verifyToken(verify2FADto.token, user.totp_secret);

    if (!isValid) {
      throw new UnauthorizedException('Invalid 2FA token');
    }

    // Enable 2FA
    user.is_two_fa_enabled = true;
    user.last_2fa_verified_at = new Date();

    await this.userRepository.save(user);

    this.logger.log(`2FA enabled for user: ${userId}`);

    return { message: '2FA enabled successfully' };
  }

  /**
   * Disable 2FA for user
   */
  async disable2FA(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.is_two_fa_enabled = false;
    user.totp_secret = null;
    user.totp_secret_created_at = null;
    user.last_2fa_verified_at = null;

    await this.userRepository.save(user);

    this.logger.log(`2FA disabled for user: ${userId}`);

    return { message: '2FA disabled successfully' };
  }

  /**
   * Generate JWT tokens
   */
  private async generateTokens(
    user: User,
    roles: string[],
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles,
    };

    const accessTokenExpiresIn = this.configService.get<string>('JWT_EXPIRES_IN') || '1h';
    const refreshTokenExpiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d';

    // Type assertion needed: expiresIn accepts string values like '1h', '7d' but TypeScript expects a specific StringValue type
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: accessTokenExpiresIn,
    } as Parameters<typeof this.jwtService.sign>[1]);

    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: refreshTokenExpiresIn,
    } as Parameters<typeof this.jwtService.sign>[1]);

    return { accessToken, refreshToken };
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(refreshToken);

      const user = await this.userRepository.findByIdWithRoles(payload.sub);

      if (!user || !user.is_active) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const roles = user.userRoles?.map((ur) => ur.role.name) || [];

      return await this.generateTokens(user, roles);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Mask email for logging (HIPAA compliance)
   */
  private maskEmail(email: string): string {
    const [localPart, domain] = email.split('@');
    if (!domain) return email;
    const maskedLocal =
      localPart.length > 2
        ? `${localPart[0]}${'*'.repeat(localPart.length - 2)}${localPart[localPart.length - 1]}`
        : '**';
    return `${maskedLocal}@${domain}`;
  }
}
