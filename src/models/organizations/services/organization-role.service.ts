import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, IsNull, Repository } from 'typeorm';
import { Organization } from '../entities/organization.entity';
import { OrganizationFeature } from '../entities/organization-feature.entity';
import { OrganizationRolePermission } from '../entities/organization-role-permission.entity';
import { OrganizationStaff } from '../staff-management/entities/organization-staff.entity';
import { OrganizationStaffRolePermission } from '../staff-management/entities/organization-staff-role-permission.entity';
import { StaffRole } from '../staff-management/entities/staff-role.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { Role } from '../../../authentication/entities/role.entity';
import { UserRole } from '../../../authentication/entities/user-role.entity';

/** Roles in the system `roles` table that confer staff app access. */
const STAFF_SYSTEM_ROLE_NAMES = [
  'STAFF',
  'ORGANIZATION',
  'OWNER',
  'HR',
  'MANAGER',
  'ASSISTANT_HR',
];

/**
 * Staff roles that are treated as power users when the org's per-role
 * `staff_role_permissions` are not yet seeded. Most orgs in the wild are
 * missing those rows, so without this fallback HR/MANAGER staff would see
 * an empty sidebar even though they semantically have full access.
 */
const POWER_STAFF_ROLES = ['HR', 'MANAGER'];

@Injectable()
export class OrganizationRoleService {
  private readonly logger = new Logger(OrganizationRoleService.name);

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
    @InjectRepository(StaffRole)
    private staffRoleRepository: Repository<StaffRole>,
    @InjectRepository(Employee)
    private employeeRepository: Repository<Employee>,
    @InjectRepository(UserRole)
    private userRoleRepository: Repository<UserRole>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
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

    let staffRows = await this.organizationStaffRepository.find({
      where: {
        user_id: userId,
        organization_id: organizationId,
        status: 'ACTIVE',
      },
      relations: ['staffRole'],
    });

    // Self-heal for dual-role users (Employee + Staff context). If the user
    // has a STAFF system role and an Employee row in this org but no
    // OrganizationStaff record, lazy-provision one with HR (broadest seeded
    // perms) so the staff dashboard, sidebar, and HR-protected APIs all
    // work without manual SQL backfill. Without this, dual-role users
    // granted via the legacy flow get empty sidebars + access denied.
    if (staffRows.length === 0) {
      const provisioned = await this.tryProvisionDualRoleStaff(
        userId,
        organizationId,
      );
      if (provisioned) staffRows = [provisioned];
    }

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

    // Power-role fallback. Most orgs in the wild were created without
    // seeding `staff_role_permissions` rows, so HR/MANAGER would have
    // no features → empty sidebar even though the role semantically has
    // full access. When perms are unseeded but the user is a power role,
    // grant full access (`*`). Once an org seeds explicit perms, those
    // win and this fallback no longer fires.
    if (features.length === 0 && staffRoleNames.some((n) => POWER_STAFF_ROLES.includes(n))) {
      return { staffRoles: staffRoleNames, features: ['*'] };
    }

    return { staffRoles: staffRoleNames, features };
  }

  /**
   * Auto-provision an `OrganizationStaff` row for dual-role users (the
   * Employee+Staff case where the user has the `STAFF` system role granted
   * but no org_staff record yet). Returns the new row, or `null` if the
   * user doesn't qualify (no STAFF role, or no Employee row in this org,
   * or no staff_role available to assign).
   *
   * Picks `HR` as the default role because it has the most seeded feature
   * permissions in practice; HR can re-assign in EditStaffDialog if a
   * different role is more appropriate.
   */
  private async tryProvisionDualRoleStaff(
    userId: string,
    organizationId: string,
  ): Promise<OrganizationStaff | null> {
    // Signal 1: user has STAFF (or another staff-side) system role.
    const userRoleLinks = await this.userRoleRepository.find({
      where: { user_id: userId },
      relations: ['role'],
    });
    const hasStaffSystemRole = userRoleLinks.some(
      (l) => l.role?.name && STAFF_SYSTEM_ROLE_NAMES.includes(l.role.name),
    );
    if (!hasStaffSystemRole) return null;

    // Signal 2: user has an Employee row in this org. This anchors them
    // to the org and confirms the dual-role intent.
    const employee = await this.employeeRepository.findOne({
      where: {
        user_id: userId,
        organization_id: organizationId,
        deleted_at: IsNull(),
      },
    });
    if (!employee) return null;

    // Pick a default staff_role with the most useful seeded perms.
    const preferred = await this.staffRoleRepository.findOne({
      where: { name: 'HR' },
    });
    const defaultRole = preferred ?? (await this.staffRoleRepository.findOne({ where: {} }));
    if (!defaultRole) {
      this.logger.warn(
        `tryProvisionDualRoleStaff: no staff_roles seeded — cannot provision for user ${userId} in org ${organizationId}`,
      );
      return null;
    }

    try {
      const created = await this.organizationStaffRepository.save(
        this.organizationStaffRepository.create({
          organization_id: organizationId,
          user_id: userId,
          staff_role_id: defaultRole.id,
          status: 'ACTIVE',
        }),
      );
      // Re-fetch with relations so the caller gets `staffRole.name`.
      return this.organizationStaffRepository.findOne({
        where: { id: created.id },
        relations: ['staffRole'],
      });
    } catch (err) {
      // Concurrent provision raced us. Re-fetch and return whatever's there.
      this.logger.log(
        `tryProvisionDualRoleStaff: concurrent provision for user ${userId} in org ${organizationId} (${err instanceof Error ? err.message : String(err)})`,
      );
      return this.organizationStaffRepository.findOne({
        where: {
          user_id: userId,
          organization_id: organizationId,
          status: 'ACTIVE',
        },
        relations: ['staffRole'],
      });
    }
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
