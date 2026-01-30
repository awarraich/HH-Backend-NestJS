import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../../authentication/interfaces/jwt-payload.interface';

@Injectable()
export class Jwt2FAPendingGuard implements CanActivate {
  private jwtService: JwtService;

  constructor(private configService: ConfigService) {
    this.jwtService = new JwtService({
      secret: this.configService.get<string>('JWT_SECRET') || 'your-secret-key',
    });
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const token = request.cookies?.accessToken || 
                  request.headers?.authorization?.replace('Bearer ', '');

    if (!token) {
      throw new UnauthorizedException('Token required');
    }

    try {
      const payload = this.jwtService.verify<JwtPayload>(token);

      if (!payload.sub || !payload.email) {
        throw new UnauthorizedException('Invalid token payload');
      }

      if (!payload.is2FAPending) {
        throw new UnauthorizedException('Token is not a 2FA pending token');
      }

      request.user = {
        userId: payload.sub,
        email: payload.email,
        roles: payload.roles || [],
        is2FAPending: true,
      };

      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
