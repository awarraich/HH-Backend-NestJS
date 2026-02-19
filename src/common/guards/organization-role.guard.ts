import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { UserWithRolesInterface } from '../interfaces/user-with-roles.interface';
import { OrganizationRoleService } from '../../models/organizations/services/organization-role.service';

@Injectable()
export class OrganizationRoleGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(forwardRef(() => OrganizationRoleService))
    private organizationRoleService: OrganizationRoleService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user: UserWithRolesInterface = request.user;
    const organizationId = request.params?.organizationId || request.body?.organizationId;

    if (!user || !user.userId) {
      throw new ForbiddenException('User not found');
    }

    if (!organizationId) {
      throw new ForbiddenException('Organization ID is required');
    }

    // Check user's roles in the specific organization (supports multiple roles per user)
    const userOrgRoles = await this.organizationRoleService.getUsersRolesInOrganization(
      user.userId,
      organizationId,
    );

    const hasRequiredRole = requiredRoles.some((r) => userOrgRoles.includes(r));

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `You do not have the required role for this organization. Required: ${requiredRoles.join(', ')}, Your roles: ${userOrgRoles.length ? userOrgRoles.join(', ') : 'none'}`,
      );
    }

    return true;
  }
}
