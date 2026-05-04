import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { GoogleChatConfigService } from '../../../config/google-chat/config.service';

interface CachedCerts {
  certs: Record<string, string>;
  fetchedAt: number;
}

@Injectable()
export class GoogleChatRequestGuard implements CanActivate {
  private readonly logger = new Logger(GoogleChatRequestGuard.name);
  private readonly CERT_TTL_MS = 60 * 60 * 1000;
  private cachedCerts: CachedCerts | null = null;

  constructor(private readonly config: GoogleChatConfigService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.config.verifySignature) {
      this.logger.warn(
        'GOOGLE_CHAT_VERIFY_SIGNATURE=false — JWT verification skipped (DEV ONLY)',
      );
      return true;
    }

    const request = context.switchToHttp().getRequest<{
      headers?: Record<string, string | undefined>;
    }>();
    const headers = request.headers ?? {};
    const authHeader = headers.authorization ?? headers.Authorization;

    if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing or malformed bearer token');
    }
    const token = authHeader.slice(7).trim();

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string' || !decoded.header?.kid) {
      throw new UnauthorizedException('Invalid token: no kid in header');
    }

    const certs = await this.getCerts();
    const cert = certs[decoded.header.kid];
    if (!cert) {
      throw new UnauthorizedException(`No matching cert for kid ${decoded.header.kid}`);
    }

    const verifyOptions: jwt.VerifyOptions = {
      algorithms: ['RS256'],
      issuer: 'https://accounts.google.com',
    };
    if (this.config.audience) {
      verifyOptions.audience = this.config.audience;
    }

    let payload: jwt.JwtPayload;
    try {
      payload = jwt.verify(token, cert, verifyOptions) as jwt.JwtPayload;
    } catch (err) {
      const msg = (err as Error).message;
      this.logger.warn(`JWT verification failed: ${msg}`);
      throw new UnauthorizedException(`Invalid Google Chat token: ${msg}`);
    }

    if (payload.email !== this.config.issuer) {
      this.logger.warn(
        `JWT sender mismatch: expected ${this.config.issuer}, got ${payload.email ?? '(none)'}`,
      );
      throw new UnauthorizedException('Token not issued by Google Chat');
    }

    return true;
  }

  private async getCerts(): Promise<Record<string, string>> {
    const now = Date.now();
    if (this.cachedCerts && now - this.cachedCerts.fetchedAt < this.CERT_TTL_MS) {
      return this.cachedCerts.certs;
    }

    const response = await fetch('https://www.googleapis.com/oauth2/v1/certs');
    if (!response.ok) {
      throw new Error(`Failed to fetch Google OIDC certs: HTTP ${response.status}`);
    }
    const certs = (await response.json()) as Record<string, string>;
    this.cachedCerts = { certs, fetchedAt: now };
    return certs;
  }
}
