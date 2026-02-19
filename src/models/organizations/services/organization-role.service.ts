import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../entities/organization.entity';
import { OrganizationRolePermission } from '../entities/organization-role-permission.entity';
import { OrganizationStaff } from '../staff-management/entities/organization-staff.entity';

@Injectable()
export class OrganizationRoleService {
  constructor(
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    @InjectRepository(OrganizationRolePermission)
    private permissionRepository: Repository<OrganizationRolePermission>,
    @InjectRepository(OrganizationStaff)
    private organizationStaffRepository: Repository<OrganizationStaff>,
  ) {}

  /**
   * Check if user is organization owner
   */
  async isOrganizationOwner(userId: string, organizationId: string): Promise<boolean> {
    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });

    return organization?.user_id === userId;
  }

  /**
   * Get all of user's roles in an organization (from organization_staff + staff_roles).
   * Returns ['OWNER'] if user owns the organization, otherwise role names from staff_roles.
   */
  async getUsersRolesInOrganization(userId: string, organizationId: string): Promise<string[]> {
    const isOwner = await this.isOrganizationOwner(userId, organizationId);
    if (isOwner) {
      return ['OWNER'];
    }

    const rows = await this.organizationStaffRepository.find({
      where: {
        user_id: userId,
        organization_id: organizationId,
        status: 'ACTIVE',
      },
      relations: ['staffRole'],
    });

    return rows.map((r) => r.staffRole.name).filter(Boolean);
  }

  /**
   * Get user's first/primary role in an organization (backward compatibility).
   * Returns 'OWNER' if owner, otherwise first staff role name or null.
   */
  async getUserRoleInOrganization(userId: string, organizationId: string): Promise<string | null> {
    const roles = await this.getUsersRolesInOrganization(userId, organizationId);
    return roles.length > 0 ? roles[0] : null;
  }

  /**
   * Check if user has role in organization
   */
  async hasRoleInOrganization(
    userId: string,
    organizationId: string,
    role: string,
  ): Promise<boolean> {
    const userRoles = await this.getUsersRolesInOrganization(userId, organizationId);
    return userRoles.includes(role);
  }

  /**
   * Check if user has any of the specified roles in organization
   */
  async hasAnyRoleInOrganization(
    userId: string,
    organizationId: string,
    roles: string[],
  ): Promise<boolean> {
    const userRoles = await this.getUsersRolesInOrganization(userId, organizationId);
    if (userRoles.includes('OWNER')) {
      return true;
    }
    return roles.some((r) => userRoles.includes(r));
  }

  /**
   * Get organization role permissions (legacy: by role name string)
   */
  async getOrganizationRolePermissions(
    organizationId: string,
    role: string,
  ): Promise<OrganizationRolePermission[]> {
    return this.permissionRepository.find({
      where: {
        organization_id: organizationId,
        role,
      },
    });
  }

  /**
   * Check if role has permission for a feature in organization
   */
  async hasPermission(organizationId: string, role: string, feature: string): Promise<boolean> {
    const permission = await this.permissionRepository.findOne({
      where: {
        organization_id: organizationId,
        role,
        feature,
      },
    });

    return permission?.has_access || false;
  }
}
