import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest<TUser = any>(
    err: any,
    user: any,
    info: any,
    context: ExecutionContext,
    status?: any,
  ): TUser {
    // Transform user object to include roles
    if (user) {
      return {
        userId: user.userId,
        email: user.email,
        roles: user.roles || [],
      } as TUser;
    }
    return super.handleRequest(err, user, info, context, status);
  }
}
