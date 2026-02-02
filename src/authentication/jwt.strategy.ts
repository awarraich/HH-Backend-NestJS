import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        (request: any) => {
          return request?.cookies?.accessToken || null;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET') || 'your-secret-key',
    });
  }

  async validate(payload: JwtPayload) {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException();
    }
    if (payload.is2FAPending) {
      throw new UnauthorizedException('2FA verification required');
    }

    // Fetch user from database to check current password_changed_at and account status
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
      select: ['id', 'email', 'password_changed_at', 'is_active'],
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.is_active) {
      throw new UnauthorizedException('User account is inactive');
    }

    // Check if password was changed after token was issued
    // Compare current database value with token issue time
    if (payload.iat && user.password_changed_at) {
      const tokenIssuedAt = payload.iat * 1000; // Convert to milliseconds
      const passwordChangedAt = new Date(user.password_changed_at).getTime();
      if (passwordChangedAt > tokenIssuedAt) {
        throw new UnauthorizedException('Password has been changed. Please log in again.');
      }
    }

    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
    };
  }
}
