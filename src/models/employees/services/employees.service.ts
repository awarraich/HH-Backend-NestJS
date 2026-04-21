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
import { CreateEmployeeByEmailDto } from '../dto/create-employee-by-email.dto';
import { CreateExternalEmployeeDto } from '../dto/create-external-employee.dto';
import { UpdateEmployeeDto } from '../dto/update-employee.dto';
import { QueryEmployeeDto } from '../dto/query-employee.dto';
import { UpdateEmployeeStatusDto } from '../dto/update-employee-status.dto';
import { InviteEmployeeDto } from '../dto/invite-employee.dto';
import { UpdateEmployeeProfileDto } from '../dto/update-employee-profile.dto';
import { EmployeeSerializer } from '../serializers/employee.serializer';
import { OrganizationRoleService } from '../../organizations/services/organization-role.service';
import { EmployeeRequirementTagService } from '../../organizations/hr-files-setup/services/employee-requirement-tag.service';
import { AvailabilityRuleService } from '../availability/services/availability-rule.service';
import { AvailabilityRule } from '../availability/entities/availability-rule.entity';
import { AuditLogService } from '../../../common/services/audit/audit-log.service';
import { AuthService } from '../../../authentication/services/auth.service';
import { EmailService } from '../../../common/services/email/email.service';
import { ConfigService } from '@nestjs/config';

const TEMPORARY_PASSWORD_EXPIRES_HOURS = 24;

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
    private authService: AuthService,
    private emailService: EmailService,
    private configService: ConfigService,
    private employeeRequirementTagService: EmployeeRequirementTagService,
    private availabilityRuleService: AvailabilityRuleService,
  ) {}

  async getAvailability(
    organizationId: string,
    employeeId: string,
  ): Promise<
    Array<{
      id: string;
      day_of_week: number | null;
      start_time: string;
      end_time: string;
      status: 'AVAILABLE' | 'UNAVAILABLE' | 'PREFERRED';
      override_date: string | null;
      organization_id: string | null;
      notes: string | null;
    }>
  > {
    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
    });

    if (!employee) {
      throw new NotFoundException(
        `Employee with ID ${employeeId} not found in organization ${organizationId}`,
      );
    }

    const rules = await this.availabilityRuleService.findByUser(
      employee.user_id,
      organizationId,
    );

    return rules.map((rule: AvailabilityRule) => {
      const isOverride =
        rule.effective_from != null &&
        rule.effective_until != null &&
        new Date(rule.effective_from).getTime() ===
          new Date(rule.effective_until).getTime();

      let status: 'AVAILABLE' | 'UNAVAILABLE' | 'PREFERRED';
      if (!rule.is_available) {
        status = 'UNAVAILABLE';
      } else if (rule.shift_type === 'preferred') {
        status = 'PREFERRED';
      } else {
        status = 'AVAILABLE';
      }

      const overrideDate = isOverride && rule.effective_from
        ? new Date(rule.effective_from).toISOString().slice(0, 10)
        : null;

      return {
        id: rule.id,
        day_of_week: rule.day_of_week,
        start_time: rule.start_time,
        end_time: rule.end_time,
        status,
        override_date: overrideDate,
        organization_id: rule.organization_id,
        notes: null,
      };
    });
  }

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

      throw new ForbiddenException(
        'You do not have permission to add employees to this organization',
      );
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
        status: 'ACTIVE',
        department: createDto.department ?? null,
        position_title: createDto.position_title ?? null,
        start_date: createDto.start_date ? new Date(createDto.start_date) : new Date(),
        end_date: createDto.end_date ? new Date(createDto.end_date) : null,
        employment_type: createDto.employment_type ?? null,
        notes: createDto.notes ?? null,
        provider_role_id: createDto.provider_role_id ?? null,
      });

      const saved = await queryRunner.manager.save(Employee, employee);

      await this.employeeRequirementTagService.assignToEmployee(
        saved.id,
        organizationId,
        createDto.requirement_tag_ids ?? [],
        queryRunner.manager,
      );

      await queryRunner.commitTransaction();
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
            provider_role_id: createDto.provider_role_id ?? null,
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
        relations: ['user', 'organization', 'profile', 'providerRole', 'employeeRequirementTags'],
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

  async createByEmail(
    organizationId: string,
    dto: CreateEmployeeByEmailDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
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
          metadata: { organization_id: organizationId, email: dto.email },
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User does not have permission to add employees',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }
      throw new ForbiddenException(
        'You do not have permission to add employees to this organization',
      );
    }

    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException(`Organization with ID ${organizationId} not found`);
    }

    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists.');
    }

    let user: User;
    let temporaryPassword: string | undefined;

    if (dto.authMethod === 'GOOGLE_SIGNIN') {
      user = await this.authService.createUserForGoogleSignIn({
        email: dto.email,
        firstName: dto.firstName,
        lastName: dto.lastName,
      });
    } else {
      const result = await this.authService.createUserWithTemporaryPasswordForEmployee({
        email: dto.email,
        firstName: dto.firstName,
        lastName: dto.lastName,
      });
      user = result.user;
      temporaryPassword = result.temporaryPassword;
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const employee = this.employeeRepository.create({
        user_id: user.id,
        organization_id: organizationId,
        status: dto.status ?? 'ACTIVE',
        start_date: dto.start_date ? new Date(dto.start_date) : new Date(),
        end_date: dto.end_date ? new Date(dto.end_date) : null,
        department: dto.department ?? null,
        position_title: dto.position_title ?? null,
        employment_type: dto.employment_type ?? null,
        notes: dto.notes ?? null,
        provider_role_id: dto.provider_role_id ?? null,
      });
      const savedEmployee = await queryRunner.manager.save(Employee, employee);

      const fullName = [dto.firstName, dto.lastName].filter(Boolean).join(' ').trim() || dto.email;
      const profile = this.employeeProfileRepository.create({
        employee_id: savedEmployee.id,
        name: fullName,
        phone_number: dto.phone_number ?? null,
        gender: dto.gender ?? null,
        date_of_birth: dto.date_of_birth ? new Date(dto.date_of_birth) : null,
        address_line_1: dto.address_line_1 ?? null,
        address_line_2: dto.address_line_2 ?? null,
        city: dto.city ?? null,
        state: dto.state ?? null,
        specialization: dto.specialization ?? null,
        years_of_experience: dto.years_of_experience ?? null,
        certification: dto.certification ?? null,
        board_certifications: dto.board_certifications ?? null,
      });
      await queryRunner.manager.save(EmployeeProfile, profile);

      await this.employeeRequirementTagService.assignToEmployee(
        savedEmployee.id,
        organizationId,
        dto.requirement_tag_ids ?? [],
        queryRunner.manager,
      );

      await queryRunner.commitTransaction();

      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          resourceId: savedEmployee.id,
          description: 'Employee created by email',
          metadata: {
            organization_id: organizationId,
            user_id: user.id,
            email: dto.email,
            provider_role_id: dto.provider_role_id ?? null,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (e) {
        this.logger.warn('Audit log failed', e);
      }

      const loginUrl = this.configService.get<string>('HOME_HEALTH_AI_URL') ?? '';
      const loginUrlPath = loginUrl ? `${loginUrl.replace(/\/$/, '')}/login` : '/login';
      try {
        if (dto.authMethod === 'GOOGLE_SIGNIN') {
          await this.emailService.sendGoogleSignInInviteEmail(
            dto.email,
            fullName,
            loginUrlPath,
            organization.organization_name ?? 'your organization',
          );
        } else {
          await this.emailService.sendOrganizationStaffCreatedEmail(
            dto.email,
            fullName,
            dto.email,
            temporaryPassword!,
            loginUrlPath,
            TEMPORARY_PASSWORD_EXPIRES_HOURS,
          );
        }
      } catch (emailError) {
        this.logger.error('Failed to send employee created email', emailError);
      }

      const employeeWithRelations = await this.employeeRepository.findOne({
        where: { id: savedEmployee.id },
        relations: ['user', 'organization', 'profile', 'providerRole', 'employeeRequirementTags'],
      });
      return this.employeeSerializer.serialize(employeeWithRelations!);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to create employee by email', error);
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          description: 'Failed to create employee by email',
          metadata: { organization_id: organizationId, email: dto.email },
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

  /**
   * Create an external employee (no organization link).
   * Creates user with temporary password, employee record, profile, and sends welcome email.
   */
  async createExternal(
    dto: CreateExternalEmployeeDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists.');
    }

    const result = await this.authService.createUserWithTemporaryPasswordForEmployee({
      email: dto.email,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });
    const user = result.user;
    const temporaryPassword = result.temporaryPassword;

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const employee = this.employeeRepository.create({
        user_id: user.id,
        organization_id: null,
        status: 'ACTIVE',
        start_date: dto.start_date ? new Date(dto.start_date) : new Date(),
        end_date: dto.end_date ? new Date(dto.end_date) : null,
        department: dto.department ?? null,
        position_title: dto.position_title ?? null,
        employment_type: dto.employment_type ?? null,
        notes: dto.notes ?? null,
      });
      const savedEmployee = await queryRunner.manager.save(Employee, employee);

      const fullName = [dto.firstName, dto.lastName].filter(Boolean).join(' ').trim() || dto.email;
      const profile = this.employeeProfileRepository.create({
        employee_id: savedEmployee.id,
        name: fullName,
        phone_number: dto.phone_number ?? null,
        gender: dto.gender ?? null,
        date_of_birth: dto.date_of_birth ? new Date(dto.date_of_birth) : null,
        address_line_1: dto.address_line_1 ?? null,
        address_line_2: dto.address_line_2 ?? null,
        city: dto.city ?? null,
        state: dto.state ?? null,
        specialization: dto.specialization ?? null,
        years_of_experience: dto.years_of_experience ?? null,
        certification: dto.certification ?? null,
        board_certifications: dto.board_certifications ?? null,
      });
      await queryRunner.manager.save(EmployeeProfile, profile);

      await queryRunner.commitTransaction();

      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          resourceId: savedEmployee.id,
          description: 'External employee created',
          metadata: {
            user_id: user.id,
            email: dto.email,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (e) {
        this.logger.warn('Audit log failed', e);
      }

      const loginUrl = this.configService.get<string>('HOME_HEALTH_AI_URL') ?? '';
      const loginUrlPath = loginUrl ? `${loginUrl.replace(/\/$/, '')}/login` : '/login';
      try {
        await this.emailService.sendOrganizationStaffCreatedEmail(
          dto.email,
          fullName,
          dto.email,
          temporaryPassword,
          loginUrlPath,
          TEMPORARY_PASSWORD_EXPIRES_HOURS,
        );
      } catch (emailError) {
        this.logger.error('Failed to send external employee created email', emailError);
      }

      const employeeWithRelations = await this.employeeRepository.findOne({
        where: { id: savedEmployee.id },
        relations: ['user', 'profile'],
      });
      return this.employeeSerializer.serialize(employeeWithRelations!);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to create external employee', error);
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'EMPLOYEE',
          description: 'Failed to create external employee',
          metadata: { email: dto.email },
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

  /**
   * List employees for an organization with optional filters and pagination.
   */
  async findAll(
    organizationId: string,
    queryDto: QueryEmployeeDto,
  ): Promise<{ data: any[]; total: number; page: number; limit: number }> {
    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException(`Organization with ID ${organizationId} not found`);
    }

    const { search, provider_role_id, status, include_orphan_employees = false, page = 1, limit = 20 } = queryDto;
    const skip = (page - 1) * limit;
    const searchTerm = search ? `%${search}%` : null;

    const queryBuilder = this.employeeRepository
      .createQueryBuilder('employee')
      .leftJoinAndSelect('employee.user', 'user')
      .leftJoinAndSelect('employee.organization', 'organization')
      .leftJoinAndSelect('employee.profile', 'profile')
      .leftJoinAndSelect('employee.providerRole', 'providerRole')
      .leftJoinAndSelect('employee.employeeRequirementTags', 'employeeRequirementTags');

    if (include_orphan_employees) {
      queryBuilder.where(
        '(employee.organization_id = :organizationId OR employee.organization_id IS NULL)',
        { organizationId },
      );
    } else {
      queryBuilder.where('employee.organization_id = :organizationId', { organizationId });
    }

    if (searchTerm) {
      // Matches single tokens (firstName/lastName/email/department/position_title)
      // AND multi-token full-name queries via CONCAT_WS, so a search like
      // "Ahmad Khan" finds users whose firstName='Ahmad' and lastName='Khan'.
      queryBuilder.andWhere(
        `(
          employee.department ILIKE :search
          OR employee.position_title ILIKE :search
          OR user.firstName ILIKE :search
          OR user.lastName ILIKE :search
          OR user.email ILIKE :search
          OR CONCAT_WS(' ', user.firstName, user.lastName) ILIKE :search
        )`,
        { search: searchTerm },
      );
    }
    if (provider_role_id) {
      queryBuilder.andWhere('employee.provider_role_id = :provider_role_id', {
        provider_role_id,
      });
    }
    if (status) {
      queryBuilder.andWhere('employee.status = :status', { status });
    }

    queryBuilder.orderBy('employee.created_at', 'DESC').skip(skip).take(limit);

    const [employees, total] = await queryBuilder.getManyAndCount();

    return {
      data: this.employeeSerializer.serializeMany(employees),
      total,
      page,
      limit,
    };
  }

  /**
   * Find employees in an organization whose provider role matches a
   * keyword (e.g. "OT", "RN", "Nurse"). Joins employees → provider_roles in
   * a single SQL query and filters in one pass — no two-step "find role id
   * then find employees by id" chain that can break on FK staleness or
   * lookup mismatches.
   *
   * Matching is exact-first (case-insensitive code or name), then fuzzy
   * (substring on code or name). The first tier that finds rows wins.
   *
   * No status filter is applied — the MCP layer chose to surface all
   * employees in a role regardless of status, so case mismatches between
   * the LLM ("ACTIVE") and the DB ("active") cannot silently zero out
   * the result.
   */
  async findByProviderRoleKeyword(
    organizationId: string,
    keyword: string,
    limit = 50,
  ): Promise<Employee[]> {
    const trimmed = keyword.trim();
    if (!trimmed) return [];
    const lower = trimmed.toLowerCase();

    const baseQuery = () =>
      this.employeeRepository
        .createQueryBuilder('employee')
        .leftJoinAndSelect('employee.user', 'user')
        .leftJoinAndSelect('employee.providerRole', 'providerRole')
        .where('employee.organization_id = :organizationId', { organizationId })
        .take(limit);

    // Tier 1: exact code/name match (case-insensitive).
    const exact = await baseQuery()
      .andWhere('(LOWER(providerRole.code) = :exact OR LOWER(providerRole.name) = :exact)', {
        exact: lower,
      })
      .getMany();
    if (exact.length > 0) return exact;

    // Tier 2: fuzzy substring on code or name.
    return baseQuery()
      .andWhere('(LOWER(providerRole.code) LIKE :fuzzy OR LOWER(providerRole.name) LIKE :fuzzy)', {
        fuzzy: `%${lower}%`,
      })
      .getMany();
  }

  /**
   * Bulk lookup of display info for a set of employees in an organization.
   * Returns a Map<employeeId, { id, name, email }> for fast enrichment of
   * tool responses that only carry raw employee_ids.
   */
  async findDisplayInfoByIds(
    organizationId: string,
    ids: string[],
  ): Promise<
    Map<
      string,
      { id: string; name: string; email: string | null; role_code: string | null }
    >
  > {
    const map = new Map<
      string,
      { id: string; name: string; email: string | null; role_code: string | null }
    >();
    if (ids.length === 0) return map;

    const employees = await this.employeeRepository
      .createQueryBuilder('employee')
      .leftJoinAndSelect('employee.user', 'user')
      .leftJoinAndSelect('employee.providerRole', 'providerRole')
      .where('employee.organization_id = :organizationId', { organizationId })
      .andWhere('employee.id IN (:...ids)', { ids })
      .getMany();

    for (const e of employees) {
      const first = e.user?.firstName ?? '';
      const last = e.user?.lastName ?? '';
      const name = `${first} ${last}`.trim() || e.user?.email || 'Unknown';
      map.set(e.id, {
        id: e.id,
        name,
        email: e.user?.email ?? null,
        role_code: e.providerRole?.code ?? null,
      });
    }
    return map;
  }

  async findOne(organizationId: string, employeeId: string): Promise<any> {
    const employee = await this.employeeRepository.findOne({
      where: {
        id: employeeId,
        organization_id: organizationId,
      },
      relations: ['user', 'organization', 'profile', 'providerRole', 'employeeRequirementTags'],
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

      throw new ForbiddenException(
        'You do not have permission to update employees in this organization',
      );
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
    if (updateDto.provider_role_id !== undefined) {
      employee.provider_role_id = updateDto.provider_role_id ?? null;
    }
    if (updateDto.employment_type !== undefined) {
      employee.employment_type = updateDto.employment_type ?? null;
    }
    if (updateDto.notes !== undefined) {
      employee.notes = updateDto.notes ?? null;
    }

    const shouldSyncTags = updateDto.requirement_tag_ids !== undefined;

    if (shouldSyncTags) {
      const queryRunner = this.dataSource.createQueryRunner();
      await queryRunner.connect();
      await queryRunner.startTransaction();
      try {
        await queryRunner.manager.save(Employee, employee);
        await this.employeeRequirementTagService.syncRequirementTagsForEmployee(
          employeeId,
          organizationId,
          updateDto.requirement_tag_ids ?? [],
          queryRunner.manager,
        );
        await queryRunner.commitTransaction();
      } catch (error) {
        await queryRunner.rollbackTransaction();
        throw error;
      } finally {
        await queryRunner.release();
      }
    } else {
      await this.employeeRepository.save(employee);
    }

    const updated = await this.employeeRepository.findOne({
      where: { id: employeeId },
    });

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
      relations: ['user', 'organization', 'profile', 'providerRole', 'employeeRequirementTags'],
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

    await this.employeeRepository.save(employee);

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

      throw new ForbiddenException(
        'You do not have permission to remove employees from this organization',
      );
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
      // Delete related data first: profile (FK from profile to employee)
      await queryRunner.manager.delete(EmployeeProfile, { employee_id: employeeId });
      await queryRunner.manager.delete(Employee, { id: employeeId });

      // Flip the linked job_application from "hired" to "terminated" so the
      // HR-facing applications list stops showing a green Hired badge for a
      // user who no longer exists as an employee. Scoped to this org's job
      // postings and the user's own applications so we never flip a row
      // outside the caller's reach. Best-effort: if there's no matching
      // hired application, skip silently (e.g. pre-hire-flow employees).
      if (employee.user_id) {
        await queryRunner.manager.query(
          `UPDATE job_applications ja
             SET status = 'terminated'
            FROM job_postings jp
           WHERE ja.job_posting_id = jp.id
             AND ja.applicant_user_id = $1
             AND jp.organization_id = $2
             AND ja.status = 'hired'`,
          [employee.user_id, organizationId],
        );
      }

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
            provider_role_id: employee.provider_role_id,
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

      throw new ForbiddenException(
        'You do not have permission to invite employees to this organization',
      );
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
        status: 'INVITED',
        department: inviteDto.department ?? null,
        position_title: inviteDto.position_title ?? null,
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

  acceptInvitation(
    _token: string,
    _userId: string,
    _ipAddress?: string,
    _userAgent?: string,
  ): Promise<never> {
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
          address_line_1: employee.profile.address_line_1,
          address_line_2: employee.profile.address_line_2,
          city: employee.profile.city,
          state: employee.profile.state,
          phone_number: employee.profile.phone_number,
          gender: employee.profile.gender,
          age: employee.profile.age,
          date_of_birth: employee.profile.date_of_birth,
          specialization: employee.profile.specialization,
          years_of_experience: employee.profile.years_of_experience,
          certification: employee.profile.certification,
          board_certifications: employee.profile.board_certifications,
          emergency_contact: employee.profile.emergency_contact,
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
        name:
          profileDto.name ||
          `${employee.user?.firstName || ''} ${employee.user?.lastName || ''}`.trim() ||
          'Employee',
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
