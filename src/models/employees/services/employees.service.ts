import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Employee } from '../entities/employee.entity';
import { EmployeeProfile } from '../entities/employee-profile.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { User } from '../../../authentication/entities/user.entity';
import { UserRepository } from '../../../authentication/repositories/user.repository';
import { CreateEmployeeDto } from '../dto/create-employee.dto';
import { UpdateEmployeeDto } from '../dto/update-employee.dto';
import { QueryEmployeeDto } from '../dto/query-employee.dto';
import { UpdateEmployeeRoleDto } from '../dto/update-employee-role.dto';
import { UpdateEmployeeStatusDto } from '../dto/update-employee-status.dto';
import { InviteEmployeeDto } from '../dto/invite-employee.dto';
import { UpdateEmployeeProfileDto } from '../dto/update-employee-profile.dto';
import { EmployeeSerializer } from '../serializers/employee.serializer';
import { OrganizationRoleService } from '../../organizations/services/organization-role.service';
import { AuditLogService } from '../../../common/services/audit/audit-log.service';
import * as crypto from 'crypto';

@Injectable()
export class EmployeesService {
  private readonly logger = new Logger(EmployeesService.name);
  private employeeSerializer = new EmployeeSerializer();

  constructor(
    @InjectRepository(Employee)
    private employeeRepository: Repository<Employee>,
    @InjectRepository(EmployeeProfile)
    private employeeProfileRepository: Repository<EmployeeProfile>,
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    private userRepository: UserRepository,
    private organizationRoleService: OrganizationRoleService,
    private dataSource: DataSource,
    private auditLogService: AuditLogService,
  ) {}

  private async validateOrganizationAccess(
    organizationId: string,
    userId: string,
    requiredRoles: string[] = ['OWNER', 'HR'],
  ): Promise<{ isOwner: boolean; hasRole: boolean }> {
    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${organizationId} not found`);
    }

    const isOwner = organization.user_id === userId;
    const userRole = await this.organizationRoleService.getUserRoleInOrganization(
      userId,
      organizationId,
    );
    const hasRole = userRole ? requiredRoles.includes(userRole) : false;

    return { isOwner, hasRole: hasRole || isOwner };
  }

  async create(
    organizationId: string,
    createDto: CreateEmployeeDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Validate organization access
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          description: 'Unauthorized employee creation attempt',
          metadata: { organization_id: organizationId, user_id: createDto.user_id },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to add employees',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to add employees to this organization');
    }

    // Check if user exists
    const user = await this.userRepository.findOne({ where: { id: createDto.user_id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${createDto.user_id} not found`);
    }

    // Check if employee already exists
    const existing = await this.employeeRepository.findOne({
      where: {
        user_id: createDto.user_id,
        organization_id: organizationId,
      },
    });

    if (existing) {
      throw new ConflictException('User is already an employee of this organization');
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const employee = this.employeeRepository.create({
        user_id: createDto.user_id,
        organization_id: organizationId,
        role: createDto.role,
        status: 'ACTIVE',
        department: createDto.department,
        position_title: createDto.position_title,
        start_date: createDto.start_date ? new Date(createDto.start_date) : new Date(),
      });

      const saved = await queryRunner.manager.save(Employee, employee);

      await queryRunner.commitTransaction();

      // HIPAA Compliance: Log operation
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          resourceId: saved.id,
          description: 'Employee added to organization',
          metadata: {
            organization_id: organizationId,
            user_id: createDto.user_id,
            role: createDto.role,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (error) {
        this.logger.error('Failed to log audit event', error);
      }

      this.logger.log(
        `Employee created: ${saved.id} in organization: ${organizationId} by user: ${userId}`,
      );

      const employeeWithRelations = await this.employeeRepository.findOne({
        where: { id: saved.id },
        relations: ['user', 'organization', 'profile'],
      });

      return this.employeeSerializer.serialize(employeeWithRelations!);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to create employee', error);

      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          description: 'Failed to create employee',
          metadata: { organization_id: organizationId, user_id: createDto.user_id },
          ipAddress,
          userAgent,
          status: 'error',
          errorMessage: error instanceof Error ? error.message : String(error),
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async findAll(organizationId: string, queryDto: QueryEmployeeDto): Promise<{
    data: any[];
    total: number;
    page: number;
    limit: number;
  }> {
    // Validate organization exists
    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${organizationId} not found`);
    }

    const { search, role, status, page = 1, limit = 20 } = queryDto;
    const skip = (page - 1) * limit;

    const queryBuilder = this.employeeRepository
      .createQueryBuilder('employee')
      .where('employee.organization_id = :organizationId', { organizationId });

    if (search) {
      queryBuilder.andWhere(
        '(employee.department ILIKE :search OR employee.position_title ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    if (role) {
      queryBuilder.andWhere('employee.role = :role', { role });
    }

    if (status) {
      queryBuilder.andWhere('employee.status = :status', { status });
    }

    queryBuilder
      .leftJoinAndSelect('employee.user', 'user')
      .leftJoinAndSelect('employee.organization', 'organization')
      .leftJoinAndSelect('employee.profile', 'profile')
      .orderBy('employee.created_at', 'DESC')
      .skip(skip)
      .take(limit);

    const [employees, total] = await queryBuilder.getManyAndCount();

    return {
      data: this.employeeSerializer.serializeMany(employees),
      total,
      page,
      limit,
    };
  }

  async findOne(organizationId: string, employeeId: string): Promise<any> {
    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
      relations: ['user', 'organization', 'profile'],
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    return this.employeeSerializer.serialize(employee);
  }

  async update(
    organizationId: string,
    employeeId: string,
    updateDto: UpdateEmployeeDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Validate organization access
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'EMPLOYEE',
          resourceId: employeeId,
          description: 'Unauthorized employee update attempt',
          metadata: { organization_id: organizationId },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to update employees',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update employees in this organization');
    }

    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    const beforeValues = { ...employee };

    if (updateDto.role) {
      employee.role = updateDto.role;
    }
    if (updateDto.department !== undefined) {
      employee.department = updateDto.department;
    }
    if (updateDto.position_title !== undefined) {
      employee.position_title = updateDto.position_title;
    }
    if (updateDto.start_date) {
      employee.start_date = new Date(updateDto.start_date);
    }
    if (updateDto.end_date !== undefined) {
      employee.end_date = updateDto.end_date ? new Date(updateDto.end_date) : null;
    }

    const updated = await this.employeeRepository.save(employee);

    // HIPAA Compliance: Log operation with before/after values
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'EMPLOYEE',
        resourceId: employeeId,
        description: 'Employee updated',
        metadata: {
          organization_id: organizationId,
          before: beforeValues,
          after: updated,
          changedFields: Object.keys(updateDto),
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(
      `Employee updated: ${employeeId} in organization: ${organizationId} by user: ${userId}`,
    );

    const employeeWithRelations = await this.employeeRepository.findOne({
      where: { id: employeeId },
      relations: ['user', 'organization', 'profile'],
    });

    return this.employeeSerializer.serialize(employeeWithRelations!);
  }

  async updateRole(
    organizationId: string,
    employeeId: string,
    roleDto: UpdateEmployeeRoleDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Validate organization access
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'EMPLOYEE',
          resourceId: employeeId,
          description: 'Unauthorized role update attempt',
          metadata: { organization_id: organizationId, new_role: roleDto.role },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to update employee roles',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update employee roles');
    }

    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    const beforeRole = employee.role;

    employee.role = roleDto.role;
    const updated = await this.employeeRepository.save(employee);

    // HIPAA Compliance: Log role change
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'EMPLOYEE',
        resourceId: employeeId,
        description: 'Employee role updated',
        metadata: {
          organization_id: organizationId,
          before_role: beforeRole,
          after_role: roleDto.role,
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(
      `Employee role updated: ${employeeId} from ${beforeRole} to ${roleDto.role} by user: ${userId}`,
    );

    const employeeWithRelations = await this.employeeRepository.findOne({
      where: { id: employeeId },
      relations: ['user', 'organization', 'profile'],
    });

    return this.employeeSerializer.serialize(employeeWithRelations!);
  }

  async updateStatus(
    organizationId: string,
    employeeId: string,
    statusDto: UpdateEmployeeStatusDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Validate organization access
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'EMPLOYEE',
          resourceId: employeeId,
          description: 'Unauthorized status update attempt',
          metadata: { organization_id: organizationId, new_status: statusDto.status },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to update employee status',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update employee status');
    }

    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    const beforeStatus = employee.status;

    employee.status = statusDto.status;
    if (statusDto.status === 'TERMINATED' && !employee.end_date) {
      employee.end_date = new Date();
    }

    const updated = await this.employeeRepository.save(employee);

    // HIPAA Compliance: Log status change
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'EMPLOYEE',
        resourceId: employeeId,
        description: 'Employee status updated',
        metadata: {
          organization_id: organizationId,
          before_status: beforeStatus,
          after_status: statusDto.status,
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(
      `Employee status updated: ${employeeId} from ${beforeStatus} to ${statusDto.status} by user: ${userId}`,
    );

    const employeeWithRelations = await this.employeeRepository.findOne({
      where: { id: employeeId },
      relations: ['user', 'organization', 'profile'],
    });

    return this.employeeSerializer.serialize(employeeWithRelations!);
  }

  async remove(
    organizationId: string,
    employeeId: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    // Validate organization access
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'EMPLOYEE',
          resourceId: employeeId,
          description: 'Unauthorized employee removal attempt',
          metadata: { organization_id: organizationId },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to remove employees',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to remove employees from this organization');
    }

    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      await queryRunner.manager.remove(Employee, employee);
      await queryRunner.commitTransaction();

      // HIPAA Compliance: Log operation
      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'EMPLOYEE',
          resourceId: employeeId,
          description: 'Employee removed from organization',
          metadata: {
            organization_id: organizationId,
            user_id: employee.user_id,
            role: employee.role,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (error) {
        this.logger.error('Failed to log audit event', error);
      }

      this.logger.log(
        `Employee removed: ${employeeId} from organization: ${organizationId} by user: ${userId}`,
      );
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to remove employee', error);

      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'EMPLOYEE',
          resourceId: employeeId,
          description: 'Failed to remove employee',
          metadata: { organization_id: organizationId },
          ipAddress,
          userAgent,
          status: 'error',
          errorMessage: error instanceof Error ? error.message : String(error),
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async invite(
    organizationId: string,
    inviteDto: InviteEmployeeDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Validate organization access
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          description: 'Unauthorized employee invitation attempt',
          metadata: { organization_id: organizationId, email: inviteDto.email },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to invite employees',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to invite employees to this organization');
    }

    // Check if user exists by email
    const user = await this.userRepository.findByEmail(inviteDto.email);
    if (!user) {
      throw new NotFoundException(`User with email ${inviteDto.email} not found`);
    }

    // Check if employee already exists
    const existing = await this.employeeRepository.findOne({
      where: {
        user_id: user.id,
        organization_id: organizationId,
      },
    });

    if (existing) {
      throw new ConflictException('User is already an employee of this organization');
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const employee = this.employeeRepository.create({
        user_id: user.id,
        organization_id: organizationId,
        role: inviteDto.role,
        status: 'INVITED',
        department: inviteDto.department,
        position_title: inviteDto.position_title,
      });

      const saved = await queryRunner.manager.save(Employee, employee);

      await queryRunner.commitTransaction();

      // HIPAA Compliance: Log invitation
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          resourceId: saved.id,
          description: 'Employee invited to organization',
          metadata: {
            organization_id: organizationId,
            user_id: user.id,
            email: inviteDto.email,
            role: inviteDto.role,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (error) {
        this.logger.error('Failed to log audit event', error);
      }

      this.logger.log(
        `Employee invited: ${saved.id} to organization: ${organizationId} by user: ${userId}`,
      );

      const employeeWithRelations = await this.employeeRepository.findOne({
        where: { id: saved.id },
        relations: ['user', 'organization', 'profile'],
      });

      return this.employeeSerializer.serialize(employeeWithRelations!);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to invite employee', error);

      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          description: 'Failed to invite employee',
          metadata: { organization_id: organizationId, email: inviteDto.email },
          ipAddress,
          userAgent,
          status: 'error',
          errorMessage: error instanceof Error ? error.message : String(error),
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async acceptInvitation(
    token: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // TODO: Implement invitation token system if needed
    // For now, this is a placeholder
    throw new BadRequestException('Invitation acceptance not yet implemented');
  }

  async getProfile(organizationId: string, employeeId: string): Promise<any> {
    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
      relations: ['profile'],
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    return employee.profile
      ? {
          id: employee.profile.id,
          employee_id: employee.profile.employee_id,
          name: employee.profile.name,
          profile_image: employee.profile.profile_image,
          address: employee.profile.address,
          phone_number: employee.profile.phone_number,
          gender: employee.profile.gender,
          age: employee.profile.age,
          emergency_contact: employee.profile.emergency_contact,
          onboarding_status: employee.profile.onboarding_status,
          created_at: employee.profile.created_at,
          updated_at: employee.profile.updated_at,
        }
      : null;
  }

  async updateProfile(
    organizationId: string,
    employeeId: string,
    profileDto: UpdateEmployeeProfileDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
      relations: ['profile'],
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    // Check if user is updating their own profile or has permission
    const isOwnProfile = employee.user_id === userId;
    const { hasRole } = await this.validateOrganizationAccess(organizationId, userId, [
      'OWNER',
      'HR',
    ]);

    if (!isOwnProfile && !hasRole) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'EMPLOYEE_PROFILE',
          resourceId: employeeId,
          description: 'Unauthorized profile update attempt',
          metadata: { organization_id: organizationId },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to update this profile',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update this employee profile');
    }

    let profile = employee.profile;
    const beforeValues = profile ? { ...profile } : null;

    if (!profile) {
      profile = this.employeeProfileRepository.create({
        employee_id: employeeId,
        name: profileDto.name || `${employee.user?.firstName || ''} ${employee.user?.lastName || ''}`.trim() || 'Employee',
      });
    }

    Object.assign(profile, profileDto);
    const updated = await this.employeeProfileRepository.save(profile);

    // HIPAA Compliance: Log operation
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'EMPLOYEE_PROFILE',
        resourceId: employeeId,
        description: 'Employee profile updated',
        metadata: {
          organization_id: organizationId,
          before: beforeValues,
          after: updated,
          changedFields: Object.keys(profileDto),
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(
      `Employee profile updated: ${employeeId} in organization: ${organizationId} by user: ${userId}`,
    );

    return this.getProfile(organizationId, employeeId);
  }
}

