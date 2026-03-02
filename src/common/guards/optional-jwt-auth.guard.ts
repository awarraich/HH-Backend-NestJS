import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UserWithRolesInterface } from '../interfaces/user-with-roles.interface';

/**
 * Like JwtAuthGuard but does not throw when there is no/invalid token.
 * Attaches user to request when token is valid; otherwise request.user is undefined.
 * Use for routes that work for both authenticated and unauthenticated callers (e.g. public blog list).
 */
@Injectable()
export class OptionalJwtAuthGuard extends AuthGuard('jwt') {
  handleRequest<TUser = UserWithRolesInterface | undefined>(
    err: any,
    user: any,
    _info: any,
    _context: ExecutionContext,
  ): TUser {
    if (user) {
      return {
        userId: user.userId,
        email: user.email,
        roles: user.roles || [],
      } as TUser;
    }
    return undefined as TUser;
  }
}
