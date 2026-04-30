import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { Employee } from '../../entities/employee.entity';
import { EmployeeProfile } from '../../entities/employee-profile.entity';
import { User } from '../../../../authentication/entities/user.entity';
import { OrganizationStaff } from '../../../organizations/staff-management/entities/organization-staff.entity';
import { UpdateEmployeeProfileDto } from '../../dto/update-employee-profile.dto';
import { EmployeeContextSerializer } from '../serializers/employee-context.serializer';
import type { OrganizationContextItem } from '../serializers/employee-context.serializer';

@Injectable()
export class EmployeeContextService {
  private readonly serializer = new EmployeeContextSerializer();

  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(EmployeeProfile)
    private readonly employeeProfileRepository: Repository<EmployeeProfile>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaffRepository: Repository<OrganizationStaff>,
  ) {}

  /**
   * Returns employee info and all organizations the employee belongs to,
   * with per-org status and is_active_context (from client's currentOrganizationId).
   * Resolves the employee from the JWT userId (no employeeId in path).
   *
   * If the user has no Employee row (no org link) but carries a
   * PROVIDER/EMPLOYEE role — i.e. an "independent employee" who signed up
   * as a provider but hasn't been hired yet — we return a synthetic
   * context with the user's basic info and `organizations: []` so the
   * frontend can render the full employee portal instead of the Jobs-only
   * applicant view. A user with neither an Employee row nor a provider
   * role is a true applicant, and we keep the 404.
   */
  async getContextByUserId(
    userId: string,
    currentOrganizationId?: string | null,
    userRoles: string[] = [],
  ): Promise<ReturnType<EmployeeContextSerializer['serializeContext']>> {
    const employee = await this.employeeRepository.findOne({
      where: { user_id: userId },
      relations: ['user', 'profile'],
      order: { created_at: 'ASC' },
    });

    if (!employee) {
      const user = await this.userRepository.findOne({ where: { id: userId } });
      if (!user) {
        throw new NotFoundException(
          'No employee record found for this user. You may not be linked to any organization.',
        );
      }

      // Org-staff path: users created via Staff Management (HR / Manager
      // / Supervisor created by an org owner) are not job applicants —
      // they belong to the organization and should land on the full
      // employee portal. They have no `Employee` row and carry the
      // system role `STAFF` (not PROVIDER/EMPLOYEE), so the legacy
      // independent-employee branch above used to 404 them and the
      // frontend dumped them onto the applicant landing.
      //
      // Synthesize a context using their `OrganizationStaff` rows as
      // the org list. The portal renders normally; org-only widgets
      // (schedule etc.) get the `is_active_context` org and behave the
      // same way they do for a directly-hired Employee.
      const staffRows = await this.orgStaffRepository.find({
        where: { user_id: userId },
        relations: ['organization', 'staffRole'],
        order: { created_at: 'ASC' },
      });

      if (staffRows.length > 0) {
        const organizations: OrganizationContextItem[] = staffRows
          .filter((row) => row.organization_id != null)
          .map((row) => ({
            organization_id: row.organization_id,
            organization_name: row.organization?.organization_name ?? null,
            employee_status: row.status, // 'ACTIVE' | 'INACTIVE' | …
            is_active_context:
              currentOrganizationId != null &&
              row.organization_id === currentOrganizationId,
            // Staff don't have a provider role; surface the staff role
            // name instead so the portal header still has something
            // sensible to print under "Role". Shape stays the same so
            // the frontend doesn't need to know it's a staff context.
            provider_role: row.staffRole
              ? {
                  id: row.staffRole.id,
                  code: row.staffRole.name,
                  name: row.staffRole.name,
                }
              : null,
          }));
        return {
          employee: {
            id: '',
            user_id: user.id,
            user: {
              id: user.id,
              email: user.email,
              firstName: user.firstName,
              lastName: user.lastName,
              is_active: user.is_active,
            },
            profile: null,
          },
          organizations,
        };
      }

      // Fall back to the existing "independent provider/employee" path
      // for users with the role but no Employee row and no staff rows.
      if (!this.hasEmployeeRole(userRoles)) {
        throw new NotFoundException(
          'No employee record found for this user. You may not be linked to any organization.',
        );
      }
      return this.serializer.serializeIndependentContext(user);
    }

    const memberships = await this.employeeRepository.find({
      where: { user_id: userId },
      relations: ['organization', 'providerRole'],
      order: { created_at: 'ASC' },
    });

    const organizations: OrganizationContextItem[] = memberships
      .filter((row) => row.organization_id != null)
      .map((row) => ({
        organization_id: row.organization_id!,
        organization_name: row.organization?.organization_name ?? null,
        employee_status: row.status,
        is_active_context:
          currentOrganizationId != null && row.organization_id === currentOrganizationId,
        provider_role: row.providerRole
          ? {
              id: row.providerRole.id,
              code: row.providerRole.code,
              name: row.providerRole.name,
            }
          : null,
      }));

    return this.serializer.serializeContext(employee, organizations);
  }

  /**
   * Update the authenticated user's "independent employee" profile.
   *
   * Independent employees are users who picked the Provider/Employee role
   * during onboarding but haven't been hired by any org — they have no
   * Employee row keyed on an `organization_id`. On first save we create a
   * placeholder Employee row with `organization_id: null` and attach an
   * EmployeeProfile to it; subsequent saves update that profile in place.
   *
   * Applicants (users with no employee-side role) are rejected with 403.
   */
  async updateIndependentProfile(
    userId: string,
    userRoles: string[],
    dto: UpdateEmployeeProfileDto,
  ): Promise<ReturnType<EmployeeContextSerializer['serializeContext']>> {
    if (!this.hasEmployeeRole(userRoles)) {
      throw new ForbiddenException(
        'Only users with the Provider or Employee role can edit an independent employee profile.',
      );
    }

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    let employee = await this.employeeRepository.findOne({
      where: { user_id: userId, organization_id: IsNull() },
      relations: ['profile'],
    });

    if (!employee) {
      employee = this.employeeRepository.create({
        user_id: userId,
        organization_id: null,
        status: 'active',
      });
      employee = await this.employeeRepository.save(employee);
    }

    let profile = employee.profile ?? null;
    if (!profile) {
      profile = this.employeeProfileRepository.create({
        employee_id: employee.id,
        name:
          dto.name ||
          `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim() ||
          'Employee',
      });
    }

    Object.assign(profile, dto);
    await this.employeeProfileRepository.save(profile);

    return this.getContextByUserId(userId, null, userRoles);
  }

  private hasEmployeeRole(userRoles: string[] = []): boolean {
    return (userRoles ?? []).some((role) => {
      const upper = String(role ?? '').toUpperCase();
      return upper === 'PROVIDER' || upper === 'EMPLOYEE';
    });
  }
}
