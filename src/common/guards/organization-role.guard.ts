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
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles || requiredRoles.length === 0) {
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

    // Fetch staff roles and assigned feature permissions in one call
    const { staffRoles, features } = await this.organizationRoleService.getStaffPermissions(
      user.userId,
      organizationId,
    );

    // Allow if the staff member has been explicitly assigned any feature access,
    // meaning they are active staff with permissions granted by the organization owner
    if (features.length > 0) {
      return true;
    }

    // OWNER always has full access
    if (staffRoles.includes('OWNER') || features.includes('*')) {
      return true;
    }

    // Allow if the staff member's role matches any of the required roles
    const hasRequiredRole = requiredRoles.some((r) => staffRoles.includes(r));
    if (hasRequiredRole) {
      return true;
    }

    // Neither a matching role nor any feature access — deny silently
    throw new ForbiddenException('You do not have access to this resource');
  }
}
