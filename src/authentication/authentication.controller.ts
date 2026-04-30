import {
  Controller,
  Post,
  Body,
  Get,
  Patch,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  BadRequestException,
  Logger,
  Redirect,
} from '@nestjs/common';
import { AuthService } from './services/auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { Authenticate2FADto } from './dto/authenticate-2fa.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { Jwt2FAPendingGuard } from '../common/guards/jwt-2fa-pending.guard';
import { GoogleOAuthGuard } from '../common/guards/google-oauth.guard';
import { SuccessHelper } from '../common/helpers/responses/success.helper';
import { RecaptchaService } from '../common/services/recaptcha/recaptcha.service';
import { AppConfigService } from '../config/app/config.service';

@Controller('v1/api/auth')
export class AuthenticationController {
  private readonly logger = new Logger(AuthenticationController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly recaptchaService: RecaptchaService,
    private readonly appConfigService: AppConfigService,
  ) {}

  private setAuthCookies(res: any, accessToken: string, refreshToken?: string): void {
    const isProduction = process.env.NODE_ENV === 'production';
    const setCookie =
      typeof res.setCookie === 'function' ? res.setCookie.bind(res) : res.cookie?.bind(res);
    if (!setCookie) {
      this.logger.warn('No cookie method on response (setCookie/cookie)');
      return;
    }
    const opts = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict' as const,
      path: '/',
    };
    if (accessToken) {
      setCookie('accessToken', accessToken, { ...opts, maxAge: 3600000 });
    }
    if (refreshToken) {
      setCookie('refreshToken', refreshToken, { ...opts, maxAge: 604800000 });
    }
  }

  private clearAuthCookies(res: any): void {
    const clearCookie =
      typeof res.clearCookie === 'function' ? res.clearCookie.bind(res) : undefined;
    if (clearCookie) {
      clearCookie('accessToken', { path: '/' });
      clearCookie('refreshToken', { path: '/' });
    }
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto, @Req() req: any) {
    const clientIp = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const result = await this.authService.register(registerDto, clientIp);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto, @Req() req: any, @Res() res: any) {
    const clientIp = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const result = await this.authService.login(loginDto, undefined, clientIp);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return res.send(
      SuccessHelper.createSuccessResponse({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        user: result.user,
        requiresTwoFactor: result.requiresTwoFactor,
        redirectPath: result.redirectPath,
      }),
    );
  }

  @Get('recaptcha/site-key')
  @HttpCode(HttpStatus.OK)
  async getRecaptchaSiteKey() {
    try {
      const siteKey = this.recaptchaService.getSiteKey();
      const enabled = this.recaptchaService.isEnabled();
      return SuccessHelper.createSuccessResponse({
        siteKey: siteKey || '',
        enabled,
      });
    } catch (error) {
      throw new BadRequestException(
        `Failed to get reCAPTCHA site key: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  async googleAuth() {
    // Initiates Google OAuth flow
  }

  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthCallback(@Req() req: any, @Res() res: any) {
    const googleProfile = req.user;
    const result = await this.authService.googleLogin(googleProfile);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    const frontendUrl = this.appConfigService.frontendUrl;
    if (!frontendUrl) {
      throw new Error('HOME_HEALTH_AI_URL or FRONTEND_URL environment variable is required');
    }
    const fragmentParams = new URLSearchParams({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: JSON.stringify(result.user),
    });
    const redirectUrl = `${frontendUrl}/auth/callback#${fragmentParams.toString()}`;

    res.redirect(redirectUrl);
  }

  // Alternative route path for compatibility: /accounts/google/login/callback/
  @Get('accounts/google/login/callback')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthCallbackAlt(@Req() req: any, @Res() res: any) {
    return this.googleAuthCallback(req, res);
  }

  @Post('login/2fa')
  @HttpCode(HttpStatus.OK)
  async loginWith2FA(@Body() loginDto: LoginDto & Authenticate2FADto, @Res() res: any) {
    const result = await this.authService.login(loginDto, loginDto.token);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return res.send(
      SuccessHelper.createSuccessResponse({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        user: result.user,
        redirectPath: result.redirectPath,
      }),
    );
  }

  @Post('login/2fa/verify')
  @UseGuards(Jwt2FAPendingGuard)
  @HttpCode(HttpStatus.OK)
  async verify2FALogin(
    @Request() req: any,
    @Body() authenticate2FADto: Authenticate2FADto,
    @Res() res: any,
  ) {
    const result = await this.authService.verify2FALogin(req.user.userId, authenticate2FADto.token);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return res.send(
      SuccessHelper.createSuccessResponse({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        user: result.user,
        redirectPath: result.redirectPath,
      }),
    );
  }

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    const result = await this.authService.verifyEmail(verifyEmailDto);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Get('verify-email')
  @Redirect()
  async verifyEmailGet(@Req() req: any) {
    const token = req.query.token;
    const frontendUrl = this.appConfigService.frontendUrl;

    if (!frontendUrl) {
      throw new BadRequestException(
        'Frontend URL not configured (set HOME_HEALTH_AI_URL or FRONTEND_URL)',
      );
    }

    if (!token) {
      return {
        url: `${frontendUrl}/login?error=${encodeURIComponent('Verification link is invalid')}`,
      };
    }

    try {
      const result = await this.authService.verifyEmail({ token });

      return {
        url: `${frontendUrl}/login?verified=true&message=${encodeURIComponent(result.message)}`,
      };
    } catch (err) {
      return {
        url: `${frontendUrl}/login?error=${encodeURIComponent(
          err instanceof Error ? err.message : 'Verification failed',
        )}`,
      };
    }
  }

  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  async resendVerification(@Body() body: { email: string }) {
    const result = await this.authService.resendVerificationEmail(body.email);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    const result = await this.authService.forgotPassword(forgotPasswordDto);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    const result = await this.authService.resetPassword(resetPasswordDto);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto, @Req() req: any, @Res() res: any) {
    const token = refreshTokenDto.refreshToken || req.cookies?.refreshToken;
    if (!token) {
      throw new BadRequestException('Refresh token is required');
    }

    const result = await this.authService.refreshToken(token);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return res.send(
      SuccessHelper.createSuccessResponse({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        user: result.user,
      }),
    );
  }

  @Post('2fa/enable')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async enable2FA(@Request() req: any) {
    const result = await this.authService.enable2FA(req.user.userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('2fa/verify')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async verify2FA(@Request() req: any, @Body() verify2FADto: Verify2FADto) {
    const result = await this.authService.verify2FASetup(req.user.userId, verify2FADto);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('2fa/disable')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async disable2FA(@Request() req: any) {
    const result = await this.authService.disable2FA(req.user.userId);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async changePassword(@Request() req: any, @Body() changePasswordDto: ChangePasswordDto) {
    const result = await this.authService.changePassword(
      req.user.userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
      changePasswordDto.confirmPassword,
    );
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Res() res: any) {
    this.clearAuthCookies(res);
    return res.send(SuccessHelper.createSuccessResponse({ message: 'Logged out successfully' }));
  }

  @Get('status')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getAuthStatus(@Request() req: any) {
    return SuccessHelper.createSuccessResponse({
      authenticated: true,
      user: req.user,
    });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMe(@Request() req: any) {
    const user = await this.authService.getCurrentUserWithRoles(req.user.userId);
    return SuccessHelper.createSuccessResponse(user);
  }

  @Get('user-info')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getUserInfo(@Request() req: any) {
    const user = await this.authService.getCurrentUserWithRoles(req.user.userId);
    return SuccessHelper.createSuccessResponse(user);
  }

  @Patch('profile')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async updateProfile(@Request() req: any, @Body() updateProfileDto: UpdateProfileDto) {
    const user = await this.authService.updateMyProfile(req.user.userId, {
      firstName: updateProfileDto.firstName,
      lastName: updateProfileDto.lastName,
    });
    return SuccessHelper.createSuccessResponse(user);
  }

  /**
   * Switch the active app context (Staff ↔ Employee) for a dual-role user.
   * Re-issues the access + refresh tokens with the new `active_role` claim
   * baked in. Validated server-side — a user without the requested context
   * gets a 400 instead of a forged switch.
   *
   * Body: { active_role: "staff" | "employee" }
   */
  @Post('switch-role')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async switchRole(
    @Request() req: any,
    @Body() body: { active_role: 'staff' | 'employee' },
    @Res() res: any,
  ) {
    const result = await this.authService.switchActiveRole(req.user.userId, body.active_role);
    this.setAuthCookies(res, result.accessToken, result.refreshToken);
    res.status(HttpStatus.OK).send(
      SuccessHelper.createSuccessResponse({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        active_role: result.active_role,
        available_roles: result.available_roles,
      }),
    );
  }
}
