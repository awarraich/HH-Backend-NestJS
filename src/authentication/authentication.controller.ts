import {
  Controller,
  Post,
  Body,
  Get,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
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
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { SuccessHelper } from '../common/helpers/responses/success.helper';

@Controller('auth')
export class AuthenticationController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    const result = await this.authService.register(registerDto);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto) {
    const result = await this.authService.login(loginDto);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('login/2fa')
  @HttpCode(HttpStatus.OK)
  async loginWith2FA(@Body() loginDto: LoginDto & Authenticate2FADto) {
    const result = await this.authService.login(loginDto, loginDto.token);
    return SuccessHelper.createSuccessResponse(result);
  }

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    const result = await this.authService.verifyEmail(verifyEmailDto);
    return SuccessHelper.createSuccessResponse(result);
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
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    const result = await this.authService.refreshToken(refreshTokenDto.refreshToken);
    return SuccessHelper.createSuccessResponse(result);
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

  @Get('status')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getAuthStatus(@Request() req: any) {
    return SuccessHelper.createSuccessResponse({
      authenticated: true,
      user: req.user,
    });
  }
}
