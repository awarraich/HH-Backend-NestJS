import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { Organization } from '../entities/organization.entity';
import { OrganizationFeature } from '../entities/organization-feature.entity';
import { OrganizationRolePermission } from '../entities/organization-role-permission.entity';
import { OrganizationStaff } from '../staff-management/entities/organization-staff.entity';
import { OrganizationStaffRolePermission } from '../staff-management/entities/organization-staff-role-permission.entity';

@Injectable()
export class OrganizationRoleService {
  constructor(
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    @InjectRepository(OrganizationRolePermission)
    private permissionRepository: Repository<OrganizationRolePermission>,
    @InjectRepository(OrganizationStaff)
    private organizationStaffRepository: Repository<OrganizationStaff>,
    @InjectRepository(OrganizationStaffRolePermission)
    private staffRolePermissionRepository: Repository<OrganizationStaffRolePermission>,
    @InjectRepository(OrganizationFeature)
    private organizationFeatureRepository: Repository<OrganizationFeature>,
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

  async getStaffPermissions(
    userId: string,
    organizationId: string,
  ): Promise<{ staffRoles: string[]; features: string[] }> {
    const isOwner = await this.isOrganizationOwner(userId, organizationId);
    if (isOwner) {
      return { staffRoles: ['OWNER'], features: ['*'] };
    }

    const staffRows = await this.organizationStaffRepository.find({
      where: {
        user_id: userId,
        organization_id: organizationId,
        status: 'ACTIVE',
      },
      relations: ['staffRole'],
    });

    if (staffRows.length === 0) {
      return { staffRoles: [], features: [] };
    }

    const staffRoleIds = staffRows.map((r) => r.staff_role_id);
    const staffRoleNames = [
      ...new Set(staffRows.map((r) => r.staffRole?.name).filter(Boolean)),
    ] as string[];

    const permissions = await this.staffRolePermissionRepository.find({
      where: {
        organization_id: organizationId,
        staff_role_id: In(staffRoleIds),
        has_access: true,
      },
      relations: ['organizationFeature'],
    });

    const features = [
      ...new Set(
        permissions
          .map((p) => p.organizationFeature?.code)
          .filter((code): code is string => Boolean(code)),
      ),
    ];
    return { staffRoles: staffRoleNames, features };
  }

  async canAccessOrganization(userId: string, organizationId: string): Promise<boolean> {
    const isOwner = await this.isOrganizationOwner(userId, organizationId);
    if (isOwner) return true;
    const count = await this.organizationStaffRepository.count({
      where: {
        user_id: userId,
        organization_id: organizationId,
        status: 'ACTIVE',
      },
    });
    return count > 0;
  }

  async getOrganizationFeatures(): Promise<{ id: string; code: string; name: string | null }[]> {
    const features = await this.organizationFeatureRepository.find({
      order: { code: 'ASC' },
    });
    return features.map((f) => ({ id: f.id, code: f.code, name: f.name }));
  }

  async getFeatureDetailsForStaffRoles(
    organizationId: string,
    staffRoleIds: string[],
  ): Promise<{ id: string; code: string; name: string | null }[]> {
    if (staffRoleIds.length === 0) return [];
    const permissions = await this.staffRolePermissionRepository.find({
      where: {
        organization_id: organizationId,
        staff_role_id: In(staffRoleIds),
        has_access: true,
      },
      relations: ['organizationFeature'],
    });
    const seen = new Set<string>();
    const result: { id: string; code: string; name: string | null }[] = [];
    for (const p of permissions) {
      const f = p.organizationFeature;
      if (f && !seen.has(f.id)) {
        seen.add(f.id);
        result.push({ id: f.id, code: f.code, name: f.name });
      }
    }
    result.sort((a, b) => a.code.localeCompare(b.code));
    return result;
  }
}
