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
import { Role } from '../entities/role.entity';
import { UserRole } from '../entities/user-role.entity';
import { EmailService } from '../../common/services/email/email.service';
import { TwoFactorService } from './two-factor.service';
import { RecaptchaService } from '../../common/services/recaptcha/recaptcha.service';
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';
import { VerifyEmailDto } from '../dto/verify-email.dto';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { Verify2FADto } from '../dto/verify-2fa.dto';
import { AuthResponseInterface } from '../interfaces/auth-response.interface';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { DataSource, Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private userRepository: UserRepository,
    private roleRepository: RoleRepository,
    private jwtService: JwtService,
    private emailService: EmailService,
    private twoFactorService: TwoFactorService,
    private recaptchaService: RecaptchaService,
    private configService: ConfigService,
    private dataSource: DataSource,
    @InjectRepository(UserRole)
    private userRoleRepository: Repository<UserRole>,
  ) {}

  /**
   * Register a new user with email verification
   */
  async register(registerDto: RegisterDto, clientIp?: string): Promise<{ message: string }> {
    if (registerDto.recaptchaToken) {
      const isValid = await this.recaptchaService.verifyToken(
        registerDto.recaptchaToken,
        clientIp,
      );
      if (!isValid) {
        throw new BadRequestException('reCAPTCHA verification failed');
      }
    } else if (this.recaptchaService.isEnabled()) {
      throw new BadRequestException('reCAPTCHA token is required');
    }

    // Check if user already exists
    const existingUser = await this.userRepository.findByEmail(registerDto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    const verificationToken = crypto.randomBytes(32).toString('hex');
    this.logger.log(`Generated verification token for ${this.maskEmail(registerDto.email)}: ${verificationToken.substring(0, 8)}... (length: ${verificationToken.length})`);

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

    const savedUser = await this.userRepository.save(user);
    
    // Verify the token was saved correctly
    const verifySaved = await this.userRepository.findOne({
      where: { id: savedUser.id },
      select: ['id', 'email', 'email_verification_token'],
    });
    
    if (verifySaved && verifySaved.email_verification_token !== verificationToken) {
      this.logger.error(`Token mismatch! Saved: ${verifySaved.email_verification_token?.substring(0, 8)}..., Expected: ${verificationToken.substring(0, 8)}...`);
    } else if (verifySaved) {
      this.logger.log(`Token saved correctly for user: ${this.maskEmail(registerDto.email)}`);
    }

    // Extract user name for email template
    const userName =
      registerDto.firstName && registerDto.lastName
        ? `${registerDto.firstName} ${registerDto.lastName}`
        : registerDto.firstName || registerDto.email;

    // Send verification email
    try {
      await this.emailService.sendVerificationEmail(
        registerDto.email,
        verificationToken,
        userName,
        registerDto.email,
      );
    } catch (error) {
      this.logger.error('Failed to send verification email', error);
    }

    this.logger.log(`User registered: ${this.maskEmail(registerDto.email)}`);

    return {
      message: 'Registration successful. Please check your email to verify your account.',
    };
  }

  /**
   * Login user with optional 2FA
   */
  async login(
    loginDto: LoginDto,
    twoFactorToken?: string,
    clientIp?: string,
  ): Promise<AuthResponseInterface> {
    // Verify reCAPTCHA if enabled
    if (loginDto.recaptchaToken) {
      const isValid = await this.recaptchaService.verifyToken(
        loginDto.recaptchaToken,
        clientIp,
      );
      if (!isValid) {
        throw new BadRequestException('reCAPTCHA verification failed');
      }
    } else if (this.recaptchaService.isEnabled()) {
      throw new BadRequestException('reCAPTCHA token is required');
    }

    const user = await this.userRepository.findByEmailWithPassword(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.password && !user.temporary_password) {
      throw new UnauthorizedException(
        'This account was created with Google. Please use Google Sign-In.',
      );
    }

    let isPasswordValid = false;
    let usedTemporaryPassword = false;

    if (user.temporary_password && user.temporary_password_expires_at) {
      const now = new Date();
      const expiresAt = new Date(user.temporary_password_expires_at);
      
      if (now > expiresAt) {
        throw new UnauthorizedException('Temporary password has expired. Please use password reset.');
      }
      
      const isTemporaryPassword = await bcrypt.compare(loginDto.password, user.temporary_password);
      
      if (isTemporaryPassword) {
        isPasswordValid = true;
        usedTemporaryPassword = true;
        user.must_change_password = true;
      } else {
        throw new UnauthorizedException('Invalid credentials. Please use your temporary password.');
      }
    } else if (user.password) {
      isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
    }

    if (!isPasswordValid) {
      this.logger.warn(`Failed login attempt for: ${this.maskEmail(loginDto.email)}`);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.is_active) {
      throw new UnauthorizedException('Account is inactive');
    }

    if (!user.email_verified) {
      throw new UnauthorizedException('Please verify your email before logging in');
    }

    if (user.is_two_fa_enabled) {
      if (!twoFactorToken) {
        const tempTokenPayload: JwtPayload = {
          sub: user.id,
          email: user.email,
          roles: [],
          is2FAPending: true,
        };

        const tempToken = this.jwtService.sign(tempTokenPayload, {
          expiresIn: '5m',
        } as Parameters<typeof this.jwtService.sign>[1]);

        return {
          accessToken: tempToken,
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

      if (!user.totp_secret) {
        throw new BadRequestException('2FA is enabled but secret is missing');
      }

      const isValid2FA = this.twoFactorService.verifyToken(twoFactorToken, user.totp_secret);

      if (!isValid2FA) {
        throw new UnauthorizedException('Invalid 2FA token');
      }

      user.last_2fa_verified_at = new Date();
    }

    user.last_login = new Date();
    if (usedTemporaryPassword) {
      user.must_change_password = true;
    }
    await this.userRepository.save(user);

    const userWithRoles = await this.userRepository.findByIdWithRoles(user.id);
    const roles = userWithRoles?.userRoles?.map((ur) => ur.role.name) || [];

    const tokens = await this.generateTokens(user, roles);

    let redirectPath = '/home';
    
    const hasAdminRole = roles.some(role => role.toLowerCase() === 'admin');
    
    if (hasAdminRole) {
      redirectPath = '/admin';
    } else if (!user.is_two_fa_enabled) {
      redirectPath = '/settings/2fa';
    }

    this.logger.log(`User logged in: ${this.maskEmail(user.email)} (Roles: ${roles.join(', ')})`);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified,
        isTwoFaEnabled: user.is_two_fa_enabled,
        roles,
        mustChangePassword: user.must_change_password,
      },
      redirectPath,
      mustChangePassword: user.must_change_password,
    };
  }

  /**
   * Verify email with token
   */
  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<{
    message: string;
  }> {
    this.logger.log(`Attempting to verify email with token: ${verifyEmailDto.token.substring(0, 8)}...`);
    
    const user = await this.userRepository.findByVerificationToken(verifyEmailDto.token);

    if (!user) {
      this.logger.warn(`Verification token not found in database: ${verifyEmailDto.token.substring(0, 8)}...`);
      
      // Check if there are any users with this token pattern (for debugging)
      const allUsers = await this.userRepository.find({
        where: {},
        select: ['id', 'email', 'email_verified', 'email_verification_token'],
      });
      
      // Check if any user is already verified (token might have been cleared)
      const verifiedUsers = allUsers.filter(u => u.email_verified);
      this.logger.debug(`Found ${verifiedUsers.length} verified users in database`);
      
      // Check if token might match a user's email (shouldn't happen, but for debugging)
      const tokenLength = verifyEmailDto.token.length;
      this.logger.debug(`Token length: ${tokenLength} (expected: 64 for 32 bytes hex)`);
      
      throw new NotFoundException('Invalid or expired verification token. The link may have already been used or expired.');
    }
    
    this.logger.log(`Found user for verification token: ${this.maskEmail(user.email)} (User ID: ${user.id})`);
    
    // Check if email is already verified
    if (user.email_verified) {
      this.logger.log(`Email already verified for: ${this.maskEmail(user.email)}`);
      return { message: 'Email is already verified' };
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

    // Verify the save was successful
    const verifiedUser = await this.userRepository.findOne({
      where: { id: user.id },
      select: ['id', 'email', 'email_verified'],
    });

    if (!verifiedUser || !verifiedUser.email_verified) {
      this.logger.error(`Email verification save failed for: ${this.maskEmail(user.email)}`);
      throw new Error('Failed to save email verification status');
    }

    this.logger.log(`Email verified successfully for: ${this.maskEmail(user.email)} (User ID: ${user.id})`);

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

    // Extract user name for email template
    const userName =
      user.firstName && user.lastName
        ? `${user.firstName} ${user.lastName}`
        : user.firstName || email;

    // Send email
    try {
      await this.emailService.sendVerificationEmail(
        email,
        verificationToken,
        userName,
        email,
      );
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

    // Extract user name for email template
    const userName =
      user.firstName && user.lastName
        ? `${user.firstName} ${user.lastName}`
        : user.firstName || forgotPasswordDto.email;

    // Send email
    try {
      await this.emailService.sendPasswordResetEmail(
        forgotPasswordDto.email,
        resetToken,
        userName,
        forgotPasswordDto.email,
      );
    } catch (error) {
      this.logger.error('Failed to send password reset email', error);
      throw new BadRequestException('Failed to send password reset email');
    }

    this.logger.log(`Password reset requested for: ${this.maskEmail(forgotPasswordDto.email)}`);

    return {
      message: 'If an account exists with this email, a password reset email has been sent.',
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    const user = await this.userRepository.findByPasswordResetToken(resetPasswordDto.token);

    if (!user) {
      throw new NotFoundException('Invalid or expired reset token');
    }

    if (!user.password_reset_sent_at) {
      throw new BadRequestException('Reset token has expired');
    }

    const tokenAge = Date.now() - new Date(user.password_reset_sent_at).getTime();
    const oneHour = 60 * 60 * 1000;

    if (tokenAge > oneHour) {
      throw new BadRequestException('Reset token has expired');
    }

    const hashedPassword = await bcrypt.hash(resetPasswordDto.newPassword, 10);

    user.password = hashedPassword;
    user.password_reset_token = null;
    user.password_reset_sent_at = null;
    user.temporary_password = null;
    user.temporary_password_expires_at = null;
    user.must_change_password = false;
    user.password_changed_at = new Date();

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

  async verify2FALogin(userId: string, twoFactorToken: string): Promise<AuthResponseInterface> {
    const user = await this.userRepository.findOne({ 
      where: { id: userId },
      select: ['id', 'email', 'email_verified', 'is_two_fa_enabled', 'totp_secret', 'is_active', 'must_change_password'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.is_two_fa_enabled) {
      throw new BadRequestException('2FA is not enabled for this user');
    }

    if (!user.totp_secret) {
      throw new BadRequestException('2FA is enabled but secret is missing');
    }

    const isValid2FA = this.twoFactorService.verifyToken(twoFactorToken, user.totp_secret);

    if (!isValid2FA) {
      throw new UnauthorizedException('Invalid 2FA token');
    }

    user.last_2fa_verified_at = new Date();
    user.last_login = new Date();
    await this.userRepository.save(user);

    const userWithRoles = await this.userRepository.findByIdWithRoles(user.id);
    const roles = userWithRoles?.userRoles?.map((ur) => ur.role.name) || [];

    const tokens = await this.generateTokens(user, roles);

    let redirectPath = '/home';
    const hasAdminRole = roles.some(role => role.toLowerCase() === 'admin');
    
    if (hasAdminRole) {
      redirectPath = '/admin';
    }

    this.logger.log(`User logged in with 2FA: ${this.maskEmail(user.email)} (Roles: ${roles.join(', ')})`);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified,
        isTwoFaEnabled: user.is_two_fa_enabled,
        roles,
        mustChangePassword: user.must_change_password,
      },
      redirectPath,
      mustChangePassword: user.must_change_password,
    };
  }

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
      passwordChangedAt: user.password_changed_at?.toISOString(),
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
   * Google OAuth login/register
   */
  async googleLogin(googleProfile: {
    googleId: string;
    email: string;
    firstName: string;
    lastName: string;
    picture?: string;
  }): Promise<AuthResponseInterface> {
    // Check if user exists by Google ID
    let user = await this.userRepository.findByGoogleId(googleProfile.googleId);

    if (!user) {
      // Check if user exists by email
      const existingUser = await this.userRepository.findByEmail(googleProfile.email);
      if (existingUser) {
        // Link Google account to existing user
        existingUser.google_id = googleProfile.googleId;
        user = existingUser;
      } else {
        // Create new user
        user = this.userRepository.create({
          firstName: googleProfile.firstName,
          lastName: googleProfile.lastName,
          email: googleProfile.email,
          google_id: googleProfile.googleId,
          email_verified: true, // Google emails are pre-verified
          is_active: true,
          password: null, // No password for OAuth users
        });
      }
    }

    // Update last login
    user.last_login = new Date();
    await this.userRepository.save(user);

    // Get user roles
    const userWithRoles = await this.userRepository.findByIdWithRoles(user.id);
    const roles = userWithRoles?.userRoles?.map((ur) => ur.role.name) || [];

    // Generate tokens
    const tokens = await this.generateTokens(user, roles);

    this.logger.log(`Google OAuth login: ${this.maskEmail(user.email)}`);

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified,
        isTwoFaEnabled: user.is_two_fa_enabled,
        roles,
        mustChangePassword: user.must_change_password,
      },
      mustChangePassword: user.must_change_password,
    };
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string): Promise<AuthResponseInterface> {
    try {
      const payload = this.jwtService.verify<JwtPayload>(refreshToken);

      const user = await this.userRepository.findByIdWithRoles(payload.sub);

      if (!user || !user.is_active) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const roles = user.userRoles?.map((ur) => ur.role.name) || [];
      const tokens = await this.generateTokens(user, roles);

      return {
        ...tokens,
        user: {
          id: user.id,
          email: user.email,
          emailVerified: user.email_verified,
          isTwoFaEnabled: user.is_two_fa_enabled,
          roles,
          mustChangePassword: user.must_change_password,
        },
        mustChangePassword: user.must_change_password,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Create user by admin
   */
  async createUserByAdmin(
    createUserDto: {
      firstName: string;
      lastName: string;
      email: string;
      password: string;
      confirmPassword: string;
      roleId: number;
    },
    adminUserId: string,
  ): Promise<{ message: string }> {
    // Validate password matches confirmPassword
    if (createUserDto.password !== createUserDto.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    // Check if email already exists
    const existingUser = await this.userRepository.findByEmail(createUserDto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Check if role exists
    const role = await this.roleRepository.findOne({
      where: { id: createUserDto.roleId },
    });
    if (!role) {
      throw new NotFoundException(`Role with ID ${createUserDto.roleId} not found`);
    }

    // Use transaction for atomicity
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Hash password
      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');

      // Create user
      const user = this.userRepository.create({
        firstName: createUserDto.firstName,
        lastName: createUserDto.lastName,
        email: createUserDto.email,
        password: hashedPassword,
        email_verification_token: verificationToken,
        email_verification_sent_at: new Date(),
        email_verified: false,
        is_active: true,
      });

      const savedUser = await queryRunner.manager.save(User, user);

      // Create UserRole record
      const userRole = queryRunner.manager.create(UserRole, {
        user_id: savedUser.id,
        role_id: createUserDto.roleId,
      });

      await queryRunner.manager.save(UserRole, userRole);

      // Commit transaction
      await queryRunner.commitTransaction();

      // Extract user name for email template
      const userName =
        createUserDto.firstName && createUserDto.lastName
          ? `${createUserDto.firstName} ${createUserDto.lastName}`
          : createUserDto.firstName || createUserDto.email;

      // Get login URL from config
      const frontendUrl =
        this.configService.get<string>('HOME_HEALTH_AI_URL') ||
        this.configService.get<string>('FRONTEND_URL') ||
        'http://127.0.0.1:5173';
      const loginUrl = `${frontendUrl}/login`;

      // Send email with password and verification link
      try {
        await this.emailService.sendAdminCreatedUserEmail(
          createUserDto.email,
          createUserDto.password, // Plain text password as requested
          verificationToken,
          userName,
          createUserDto.email,
          loginUrl,
        );
      } catch (error) {
        this.logger.error(
          `Failed to send admin-created user email to: ${this.maskEmail(createUserDto.email)}`,
          error,
        );
        // Don't throw - user is created, email failure is logged
      }

      this.logger.log(
        `User created by admin ${this.maskEmail(adminUserId)}: ${this.maskEmail(createUserDto.email)} (Role: ${role.name})`,
      );

      return {
        message: 'User created successfully. An email with login credentials has been sent.',
      };
    } catch (error) {
      // Rollback transaction on error
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to create user by admin: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    } finally {
      // Release query runner
      await queryRunner.release();
    }
  }

  /**
   * Create a user with temporary password (e.g. for organization staff).
   * Assigns EMPLOYEE system role. Caller must create organization_staff record(s) and send email.
   */
  async createUserWithTemporaryPassword(dto: {
    email: string;
    firstName: string;
    lastName: string;
  }): Promise<{ user: User; temporaryPassword: string }> {
    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const employeeRole = await this.roleRepository.findByName('EMPLOYEE');
    if (!employeeRole) {
      throw new NotFoundException('EMPLOYEE role not found. Ensure roles are seeded.');
    }

    const temporaryPassword = this.generateTemporaryPassword();
    const hashedTemporaryPassword = await bcrypt.hash(temporaryPassword, 10);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const user = this.userRepository.create({
        firstName: dto.firstName,
        lastName: dto.lastName,
        email: dto.email,
        password: null,
        temporary_password: hashedTemporaryPassword,
        temporary_password_expires_at: expiresAt,
        must_change_password: true,
        email_verified: true,
        is_active: true,
      });

      const savedUser = await queryRunner.manager.save(User, user);

      const userRole = queryRunner.manager.create(UserRole, {
        user_id: savedUser.id,
        role_id: employeeRole.id,
      });
      await queryRunner.manager.save(UserRole, userRole);

      await queryRunner.commitTransaction();

      this.logger.log(
        `User created with temporary password: ${this.maskEmail(dto.email)} (for organization staff)`,
      );

      return { user: savedUser, temporaryPassword };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to create user with temporary password: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Get all users with their roles (paginated)
   * Excludes the current admin user
   */
  async getAllUsersWithRoles(
    page: number = 1,
    limit: number = 20,
    search?: string,
    roleId?: number,
    excludeUserId?: string,
  ): Promise<{ users: any[]; total: number; page: number; limit: number }> {
    const skip = (page - 1) * limit;
    const queryBuilder = this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.userRoles', 'userRoles')
      .leftJoinAndSelect('userRoles.role', 'role');

    // Exclude current admin user
    if (excludeUserId) {
      queryBuilder.where('user.id != :excludeUserId', { excludeUserId });
    }

    if (search) {
      const searchCondition = '(user.firstName ILIKE :search OR user.lastName ILIKE :search OR user.email ILIKE :search)';
      if (excludeUserId) {
        queryBuilder.andWhere(searchCondition, { search: `%${search}%` });
      } else {
        queryBuilder.where(searchCondition, { search: `%${search}%` });
      }
    }

    if (roleId) {
      const roleCondition = 'role.id = :roleId';
      if (excludeUserId || search) {
        queryBuilder.andWhere(roleCondition, { roleId });
      } else {
        queryBuilder.where(roleCondition, { roleId });
      }
    }

    const [users, total] = await queryBuilder
      .orderBy('user.created_at', 'DESC')
      .skip(skip)
      .take(limit)
      .getManyAndCount();

    const usersWithRoles = users.map((user) => ({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      is_active: user.is_active,
      email_verified: user.email_verified,
      is_two_fa_enabled: user.is_two_fa_enabled,
      last_login: user.last_login,
      created_at: user.created_at,
      updated_at: user.updated_at,
      roles: user.userRoles?.map((ur) => ({
        id: ur.role.id,
        name: ur.role.name,
        description: ur.role.description,
      })) || [],
    }));

    return {
      users: usersWithRoles,
      total,
      page,
      limit,
    };
  }

  /**
   * Get user by ID with roles
   */
  async getUserByIdWithRoles(userId: string): Promise<any> {
    const user = await this.userRepository.findByIdWithRoles(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      is_active: user.is_active,
      email_verified: user.email_verified,
      is_two_fa_enabled: user.is_two_fa_enabled,
      last_login: user.last_login,
      created_at: user.created_at,
      updated_at: user.updated_at,
      roles: user.userRoles?.map((ur) => ({
        id: ur.role.id,
        name: ur.role.name,
        description: ur.role.description,
      })) || [],
    };
  }

  /**
   * Update user by admin
   */
  async updateUserByAdmin(
    userId: string,
    updateDto: {
      firstName?: string;
      lastName?: string;
      email?: string;
      password?: string;
      is_active?: boolean;
      email_verified?: boolean;
      roleId?: number;
    },
    adminUserId: string,
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if email is being changed and if it's already taken
    if (updateDto.email && updateDto.email !== user.email) {
      const existingUser = await this.userRepository.findByEmail(updateDto.email);
      if (existingUser) {
        throw new ConflictException('Email is already taken by another user');
      }
    }

    // Track changes for email notification
    const changes: {
      password?: boolean;
      temporaryPassword?: string;
      email?: { old: string; new: string };
      firstName?: { old: string; new: string };
      lastName?: { old: string; new: string };
      role?: { old: string; new: string };
    } = {};

    // Get old role name if role is being changed
    let oldRoleName: string | undefined;
    if (updateDto.roleId !== undefined) {
      const userWithRoles = await this.userRepository.findByIdWithRoles(userId);
      oldRoleName = userWithRoles?.userRoles?.[0]?.role?.name;
    }

    // Use transaction for atomicity
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Track changes before updating
      if (updateDto.firstName !== undefined && updateDto.firstName !== user.firstName) {
        changes.firstName = { old: user.firstName, new: updateDto.firstName };
      }
      if (updateDto.lastName !== undefined && updateDto.lastName !== user.lastName) {
        changes.lastName = { old: user.lastName, new: updateDto.lastName };
      }
      if (updateDto.email !== undefined && updateDto.email !== user.email) {
        changes.email = { old: user.email, new: updateDto.email };
      }
      if (updateDto.password) {
        changes.password = true;
      }

      // Update user fields
      if (updateDto.firstName !== undefined) {
        user.firstName = updateDto.firstName;
      }
      if (updateDto.lastName !== undefined) {
        user.lastName = updateDto.lastName;
      }
      if (updateDto.email !== undefined) {
        user.email = updateDto.email;
      }
      if (updateDto.is_active !== undefined) {
        user.is_active = updateDto.is_active;
      }
      if (updateDto.email_verified !== undefined) {
        user.email_verified = updateDto.email_verified;
      }

      if (updateDto.password) {
        const temporaryPassword = this.generateTemporaryPassword();
        const hashedTemporaryPassword = await bcrypt.hash(temporaryPassword, 10);
        
        user.temporary_password = hashedTemporaryPassword;
        user.temporary_password_expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000);
        user.must_change_password = true;
        
        user.password = await bcrypt.hash(updateDto.password, 10);
        user.password_changed_at = new Date();
        
        changes.temporaryPassword = temporaryPassword;
      }

      await queryRunner.manager.save(User, user);

      // Update role if provided
      let newRoleName: string | undefined;
      if (updateDto.roleId !== undefined) {
        // Verify role exists
        const role = await this.roleRepository.findOne({
          where: { id: updateDto.roleId },
        });
        if (!role) {
          throw new NotFoundException(`Role with ID ${updateDto.roleId} not found`);
        }

        newRoleName = role.name;

        // Delete existing user roles
        await queryRunner.manager.delete(UserRole, { user_id: userId });

        // Create new user role
        const userRole = queryRunner.manager.create(UserRole, {
          user_id: userId,
          role_id: updateDto.roleId,
        });
        await queryRunner.manager.save(UserRole, userRole);

        if (oldRoleName !== newRoleName) {
          changes.role = { old: oldRoleName || 'None', new: newRoleName };
        }
      }

      await queryRunner.commitTransaction();

      // Send email notification if sensitive fields changed (password or email) or any changes
      const hasSensitiveChanges = changes.password || changes.email;
      const hasAnyChanges = Object.keys(changes).length > 0;

      if (hasAnyChanges) {
        try {
          const frontendUrl =
            this.configService.get<string>('HOME_HEALTH_AI_URL') ||
            this.configService.get<string>('FRONTEND_URL') ||
            'http://127.0.0.1:5173';
          const loginUrl = `${frontendUrl}/login`;

          // Extract user name for email template
          const userName =
            user.firstName && user.lastName
              ? `${user.firstName} ${user.lastName}`
              : user.firstName || user.email;

          // Use the new email if it was changed, otherwise use the old one
          const emailToSend = changes.email?.new || user.email;

          await this.emailService.sendAdminUpdatedUserEmail(
            emailToSend,
            userName,
            emailToSend,
            changes,
            loginUrl,
          );
        } catch (error) {
          this.logger.error(
            `Failed to send admin-updated user email to: ${this.maskEmail(user.email)}`,
            error,
          );
          // Don't throw - user is updated, email failure is logged
        }
      }

      this.logger.log(
        `User updated by admin ${this.maskEmail(adminUserId)}: ${this.maskEmail(user.email)}${hasSensitiveChanges ? ' (Sensitive changes - user logged out)' : ''}`,
      );

      return {
        message: 'User updated successfully' + (hasSensitiveChanges ? '. User has been notified and logged out.' : ''),
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to update user by admin: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
    confirmPassword: string,
  ): Promise<{ message: string }> {
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match');
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: [
        'id',
        'password',
        'temporary_password',
        'temporary_password_expires_at',
        'must_change_password',
      ],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    let isValidPassword = false;

    if (user.password) {
      isValidPassword = await bcrypt.compare(oldPassword, user.password);
    }

    if (!isValidPassword && user.temporary_password) {
      const isTemporaryPassword = await bcrypt.compare(oldPassword, user.temporary_password);
      if (isTemporaryPassword) {
        isValidPassword = true;
      }
    }

    if (!isValidPassword) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.temporary_password = null;
    user.temporary_password_expires_at = null;
    user.must_change_password = false;
    user.password_changed_at = new Date();

    await this.userRepository.save(user);

    this.logger.log(`Password changed for user: ${userId}`);

    return { message: 'Password changed successfully' };
  }

  /**
   * Delete user by admin
   */
  async deleteUserByAdmin(
    userId: string,
    adminUserId: string,
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Prevent admin from deleting themselves
    if (userId === adminUserId) {
      throw new BadRequestException('You cannot delete your own account');
    }

    // Use transaction for atomicity
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const userEmail = user.email;

      // Delete user (cascade will handle user_roles deletion automatically)
      await queryRunner.manager.remove(User, user);

      await queryRunner.commitTransaction();

      this.logger.log(
        `User deleted by admin ${this.maskEmail(adminUserId)}: ${this.maskEmail(userEmail)}`,
      );

      return {
        message: 'User deleted successfully',
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to delete user by admin: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  private generateTemporaryPassword(): string {
    const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lowercase = 'abcdefghijkmnpqrstuvwxyz';
    const numbers = '23456789';
    const special = '!@#$%&*';
    const allChars = uppercase + lowercase + numbers + special;

    let password = '';
    
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];

    for (let i = password.length; i < 12; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    return password.split('').sort(() => Math.random() - 0.5).join('');
  }

  async getPublicRoles(): Promise<Role[]> {
    const roleNames = ['ORGANIZATION', 'PATIENT', 'EMPLOYEE'];
    const roles = await this.roleRepository
      .createQueryBuilder('role')
      .where('role.name IN (:...roleNames)', { roleNames })
      .orderBy('role.id', 'ASC')
      .getMany();

    return roles;
  }

  async assignRoleToUser(userId: string, roleId: number): Promise<any> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    const role = await this.roleRepository.findOne({ where: { id: roleId } });
    if (!role) {
      throw new NotFoundException(`Role with ID ${roleId} not found`);
    }

    const existingUserRole = await this.userRoleRepository.findOne({
      where: { user_id: userId, role_id: roleId },
    });

    if (existingUserRole) {
      throw new ConflictException(`User already has role ${role.name}`);
    }

    const userRole = this.userRoleRepository.create({
      user_id: userId,
      role_id: roleId,
    });

    await this.userRoleRepository.save(userRole);

    this.logger.log(
      `Role assigned: User ${this.maskEmail(user.email)} assigned role ${role.name}`,
    );

    return {
      id: userRole.id,
      user_id: userRole.user_id,
      role_id: userRole.role_id,
      role: {
        id: role.id,
        name: role.name,
        description: role.description,
      },
      created_at: userRole.created_at,
    };
  }

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
