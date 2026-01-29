import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { GoogleOAuthGuard } from '../common/guards/google-oauth.guard';
import { AuthService } from './services/auth.service';

/**
 * OAuth callback controller - registered without API prefix
 * Handles: /accounts/google/login/callback/
 */
@Controller()
export class GoogleOAuthCallbackController {
  constructor(private readonly authService: AuthService) {}

  @Get('accounts/google/login/callback')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthCallback(@Req() req: any, @Res() res: any) {
    const googleProfile = req.user;
    const result = await this.authService.googleLogin(googleProfile);

    // Redirect to frontend with tokens
    const frontendUrl = process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL;
    if (!frontendUrl) {
      throw new Error('HOME_HEALTH_AI_URL or FRONTEND_URL environment variable is required');
    }
    const redirectUrl = `${frontendUrl}/auth/callback?accessToken=${result.accessToken}&refreshToken=${result.refreshToken}`;
    
    res.redirect(redirectUrl);
  }
}

