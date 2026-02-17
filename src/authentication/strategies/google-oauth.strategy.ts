import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { GoogleOAuthConfigService } from '../../config/google-oauth/config.service';

@Injectable()
export class GoogleOAuthStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private googleOAuthConfigService: GoogleOAuthConfigService) {
    super({
      clientID: googleOAuthConfigService.clientId,
      clientSecret: googleOAuthConfigService.clientSecret,
      callbackURL: googleOAuthConfigService.callbackURL,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    if (!profile) {
      return done(
        new UnauthorizedException('No profile received from Google'),
        undefined,
      );
    }

    const { id, name, emails, photos } = profile;

    if (!emails || emails.length === 0) {
      return done(
        new UnauthorizedException('No email found in Google profile'),
        undefined,
      );
    }

    const email = emails[0].value;
    const firstName = name?.givenName || '';
    const lastName = name?.familyName || '';
    const picture = photos?.[0]?.value || null;

    const user = {
      googleId: id,
      email,
      firstName,
      lastName,
      picture,
      accessToken,
    };

    done(null, user);
  }
}

