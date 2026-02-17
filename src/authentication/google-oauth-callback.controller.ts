import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { GoogleOAuthGuard } from '../common/guards/google-oauth.guard';
import { AuthService } from './services/auth.service';
import { AppConfigService } from '../config/app/config.service';

/**
 * OAuth callback controller - registered without API prefix.
 * Handles: /accounts/google/login/callback
 * Uses same redirect logic as AuthenticationController (fragment + cookies).
 */
@Controller()
export class GoogleOAuthCallbackController {
  constructor(
    private readonly authService: AuthService,
    private readonly appConfigService: AppConfigService,
  ) {}

  @Get('accounts/google/login/callback')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthCallback(@Req() req: any, @Res() res: any) {
    const googleProfile = req.user;
    const result = await this.authService.googleLogin(googleProfile);

    const frontendUrl = this.appConfigService.frontendUrl;
    if (!frontendUrl) {
      throw new Error(
        'HOME_HEALTH_AI_URL or FRONTEND_URL environment variable is required',
      );
    }

    const fragmentParams = new URLSearchParams({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: JSON.stringify(result.user),
    });
    const redirectUrl = `${frontendUrl}/auth/callback#${fragmentParams.toString()}`;

    const isProduction = process.env.NODE_ENV === 'production';
    res.cookie('accessToken', result.accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 3600000,
      path: '/',
    });
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      maxAge: 604800000,
      path: '/',
    });

    res.redirect(redirectUrl);
  }
}

