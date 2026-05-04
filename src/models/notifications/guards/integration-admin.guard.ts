import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../organizations/entities/organization.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import type { UserWithRolesInterface } from '../../../common/interfaces/user-with-roles.interface';

/**
 * Authorization for the org-admin integration endpoints.
 * Allows access if the actor is either:
 *   - The organization owner (`organizations.user_id` matches actor.userId), OR
 *   - An ACTIVE staff member with role `HR` or `MANAGER`.
 *
 * The previous implementation used the project-wide `OrganizationRoleGuard`
 * which only checks `organization_staff` — that excluded the org owner from
 * managing their own integration unless they were also explicitly added as
 * staff. This guard fixes that asymmetry while keeping the staff-role gate
 * intact for non-owner admins.
 */
@Injectable()
export class IntegrationAdminGuard implements CanActivate {
  private static readonly ALLOWED_ROLES = ['HR', 'MANAGER'];

  constructor(
    @InjectRepository(Organization)
    private readonly orgs: Repository<Organization>,
    @InjectRepository(OrganizationStaff)
    private readonly staff: Repository<OrganizationStaff>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<{
      user?: UserWithRolesInterface;
      params?: Record<string, string | undefined>;
    }>();
    const user = request.user;
    const orgId = request.params?.organizationId;

    if (!user?.userId) throw new ForbiddenException('Authentication required');
    if (!orgId) throw new ForbiddenException('organizationId is required');

    const org = await this.orgs.findOne({ where: { id: orgId } });
    if (!org) throw new NotFoundException(`Organization ${orgId} not found`);

    if (org.user_id === user.userId) return true;

    const staffRow = await this.staff
      .createQueryBuilder('os')
      .innerJoinAndSelect('os.staffRole', 'sr')
      .where('os.user_id = :userId', { userId: user.userId })
      .andWhere('os.organization_id = :orgId', { orgId })
      .andWhere('os.status = :status', { status: 'ACTIVE' })
      .andWhere('sr.name IN (:...roles)', { roles: IntegrationAdminGuard.ALLOWED_ROLES })
      .getOne();

    if (staffRow) return true;

    throw new ForbiddenException(
      'You do not have access to this integration. Owner or HR/MANAGER staff role required.',
    );
  }
}
