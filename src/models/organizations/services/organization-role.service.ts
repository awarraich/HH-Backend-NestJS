import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../entities/organization.entity';
import { OrganizationRolePermission } from '../entities/organization-role-permission.entity';
import { Employee } from '../../employees/entities/employee.entity';

@Injectable()
export class OrganizationRoleService {
  private readonly logger = new Logger(OrganizationRoleService.name);

  constructor(
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    @InjectRepository(OrganizationRolePermission)
    private permissionRepository: Repository<OrganizationRolePermission>,
    @InjectRepository(Employee)
    private employeeRepository: Repository<Employee>,
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
   * Get user's role in an organization
   * Returns 'OWNER' if user owns the organization, otherwise returns employee role
   */
  async getUserRoleInOrganization(userId: string, organizationId: string): Promise<string | null> {
    // First check if user is the organization owner
    const isOwner = await this.isOrganizationOwner(userId, organizationId);
    if (isOwner) {
      return 'OWNER';
    }

    // Otherwise check if user is an employee
    const employee = await this.employeeRepository.findOne({
      where: {
        user_id: userId,
        organization_id: organizationId,
        status: 'ACTIVE',
      },
    });

    return employee?.role || null;
  }

  /**
   * Check if user has role in organization
   */
  async hasRoleInOrganization(
    userId: string,
    organizationId: string,
    role: string,
  ): Promise<boolean> {
    const userRole = await this.getUserRoleInOrganization(userId, organizationId);
    return userRole === role;
  }

  /**
   * Check if user has any of the specified roles in organization
   */
  async hasAnyRoleInOrganization(
    userId: string,
    organizationId: string,
    roles: string[],
  ): Promise<boolean> {
    const userRole = await this.getUserRoleInOrganization(userId, organizationId);
    // OWNER has access to everything, so if OWNER is in required roles, check ownership
    if (roles.includes('OWNER')) {
      const isOwner = await this.isOrganizationOwner(userId, organizationId);
      if (isOwner) {
        return true;
      }
    }
    return userRole ? roles.includes(userRole) : false;
  }

  /**
   * Get organization role permissions
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
