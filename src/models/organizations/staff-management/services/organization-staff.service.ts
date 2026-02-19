import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, In } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { OrganizationStaff } from '../entities/organization-staff.entity';
import { StaffRole } from '../entities/staff-role.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { AuthService } from '../../../../authentication/services/auth.service';
import { EmailService } from '../../../../common/services/email/email.service';
import { AuditLogService } from '../../../../common/services/audit/audit-log.service';
import { CreateOrganizationStaffDto } from '../dto/create-organization-staff.dto';
import { QueryOrganizationStaffDto } from '../dto/query-organization-staff.dto';
import { UpdateOrganizationStaffDto } from '../dto/update-organization-staff.dto';

const TEMPORARY_PASSWORD_EXPIRES_HOURS = 24;

@Injectable()
export class OrganizationStaffService {
  private readonly logger = new Logger(OrganizationStaffService.name);

  constructor(
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    @InjectRepository(OrganizationStaff)
    private organizationStaffRepository: Repository<OrganizationStaff>,
    @InjectRepository(StaffRole)
    private staffRoleRepository: Repository<StaffRole>,
    private organizationRoleService: OrganizationRoleService,
    private authService: AuthService,
    private emailService: EmailService,
    private configService: ConfigService,
    private dataSource: DataSource,
    private auditLogService: AuditLogService,
  ) {}

  /**
   * List all staff roles from DB (no hardcoded roles).
   */
  async findAllStaffRoles(): Promise<{ id: string; name: string; description: string | null }[]> {
    const roles = await this.staffRoleRepository.find({
      order: { name: 'ASC' },
    });
    return roles.map((r) => ({ id: r.id, name: r.name, description: r.description }));
  }

  /**
   * Create staff user with temporary password and assign role(s). Only organization owner can create.
   */
  async createStaff(
    organizationId: string,
    dto: CreateOrganizationStaffDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ id: string; user_id: string; email: string; roles: { id: string; name: string }[] }> {
    const isOwner = await this.organizationRoleService.isOrganizationOwner(userId, organizationId);
    if (!isOwner) {
      await this.auditLogService.log({
        userId,
        action: 'CREATE',
        resourceType: 'ORGANIZATION_STAFF',
        description: 'Unauthorized staff creation attempt',
        metadata: { organization_id: organizationId },
        ipAddress,
        userAgent,
        status: 'failure',
      });
      throw new ForbiddenException('Only the organization owner can create staff.');
    }

    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }

    const staffRoles = await this.staffRoleRepository.find({
      where: { id: In(dto.staff_role_ids) },
    });
    if (staffRoles.length !== dto.staff_role_ids.length) {
      throw new BadRequestException('One or more staff role IDs are invalid.');
    }

    const { user, temporaryPassword } = await this.authService.createUserWithTemporaryPassword({
      email: dto.email,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const createdRows: OrganizationStaff[] = [];
      for (const role of staffRoles) {
        const row = queryRunner.manager.create(OrganizationStaff, {
          organization_id: organizationId,
          user_id: user.id,
          staff_role_id: role.id,
          status: 'ACTIVE',
          department: dto.department,
          position_title: dto.position_title,
          start_date: new Date(),
          created_by: userId,
          updated_by: userId,
        });
        const saved = await queryRunner.manager.save(OrganizationStaff, row);
        createdRows.push(saved);
      }

      await queryRunner.commitTransaction();

      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'ORGANIZATION_STAFF',
          resourceId: user.id,
          description: 'Staff created',
          metadata: {
            organization_id: organizationId,
            user_id: user.id,
            email: dto.email,
            staff_role_ids: dto.staff_role_ids,
          },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (e) {
        this.logger.warn('Audit log failed', e);
      }

      const loginUrl = this.configService.get<string>('HOME_HEALTH_AI_URL')
      const loginUrlPath = `${loginUrl}/login`;
      const userName = [dto.firstName, dto.lastName].filter(Boolean).join(' ') || dto.email;

      try {
        await this.emailService.sendOrganizationStaffCreatedEmail(
          dto.email,
          userName,
          dto.email,
          temporaryPassword,
          loginUrlPath,
          TEMPORARY_PASSWORD_EXPIRES_HOURS,
        );
      } catch (emailError) {
        this.logger.error('Failed to send staff created email', emailError);
        // Don't fail the request - user and staff are created
      }

      return {
        id: user.id,
        user_id: user.id,
        email: user.email,
        roles: staffRoles.map((r) => ({ id: r.id, name: r.name })),
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      await this.auditLogService.log({
        userId,
        action: 'CREATE',
        resourceType: 'ORGANIZATION_STAFF',
        description: 'Failed to create staff',
        metadata: { organization_id: organizationId, email: dto.email },
        ipAddress,
        userAgent,
        status: 'error',
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * List staff in organization (grouped by user with their roles).
   */
  async findAll(
    organizationId: string,
    queryDto: QueryOrganizationStaffDto,
    userId: string,
  ): Promise<{ data: any[]; total: number; page: number; limit: number }> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(userId, organizationId, [
      'OWNER',
      'HR',
      'MANAGER',
    ]);
    if (!canAccess) {
      throw new ForbiddenException('You do not have permission to list staff in this organization.');
    }

    const organization = await this.organizationRepository.findOne({ where: { id: organizationId } });
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }

    const { page = 1, limit = 20, staff_role_id, status, search } = queryDto;
    const skip = (page - 1) * limit;

    const qb = this.organizationStaffRepository
      .createQueryBuilder('os')
      .innerJoinAndSelect('os.user', 'user')
      .innerJoinAndSelect('os.staffRole', 'staffRole')
      .where('os.organization_id = :organizationId', { organizationId });

    if (staff_role_id) {
      qb.andWhere('os.staff_role_id = :staff_role_id', { staff_role_id });
    }
    if (status) {
      qb.andWhere('os.status = :status', { status });
    }
    if (search) {
      qb.andWhere(
        '(user.firstName ILIKE :search OR user.lastName ILIKE :search OR user.email ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    qb.orderBy('os.created_at', 'DESC');

    const [rows, total] = await qb.skip(skip).take(limit).getManyAndCount();

    const byUser = new Map<
      string,
      { user_id: string; email: string; firstName: string; lastName: string; roles: any[]; status: string; department: string | null; position_title: string | null }
    >();
    for (const row of rows) {
      const u = row.user;
      if (!byUser.has(row.user_id)) {
        byUser.set(row.user_id, {
          user_id: row.user_id,
          email: u.email,
          firstName: u.firstName,
          lastName: u.lastName,
          roles: [],
          status: row.status,
          department: row.department,
          position_title: row.position_title,
        });
      }
      const rec = byUser.get(row.user_id)!;
      rec.roles.push({ id: row.staffRole.id, name: row.staffRole.name });
    }

    const data = Array.from(byUser.values());

    return { data, total, page, limit };
  }

  /**
   * Get one staff member (by user_id in this org) with all their roles.
   */
  async findOneByUserId(
    organizationId: string,
    staffUserId: string,
    userId: string,
  ): Promise<{ user_id: string; email: string; firstName: string; lastName: string; roles: any[]; status: string; department: string | null; position_title: string | null }> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(userId, organizationId, [
      'OWNER',
      'HR',
      'MANAGER',
    ]);
    if (!canAccess) {
      throw new ForbiddenException('You do not have permission to view this staff member.');
    }

    const rows = await this.organizationStaffRepository.find({
      where: { organization_id: organizationId, user_id: staffUserId },
      relations: ['user', 'staffRole'],
    });
    if (!rows.length) {
      throw new NotFoundException('Staff member not found in this organization.');
    }

    const u = rows[0].user;
    return {
      user_id: u.id,
      email: u.email,
      firstName: u.firstName,
      lastName: u.lastName,
      roles: rows.map((r) => ({ id: r.staffRole.id, name: r.staffRole.name })),
      status: rows[0].status,
      department: rows[0].department,
      position_title: rows[0].position_title,
    };
  }

  /**
   * Update staff member (status, department, position_title for all their role rows).
   */
  async updateStaff(
    organizationId: string,
    staffUserId: string,
    dto: UpdateOrganizationStaffDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    const isOwner = await this.organizationRoleService.isOrganizationOwner(userId, organizationId);
    const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(userId, organizationId, ['OWNER', 'HR', 'MANAGER']);
    if (!isOwner && !hasRole) {
      throw new ForbiddenException('You do not have permission to update staff.');
    }

    const rows = await this.organizationStaffRepository.find({
      where: { organization_id: organizationId, user_id: staffUserId },
    });
    if (!rows.length) {
      throw new NotFoundException('Staff member not found in this organization.');
    }

    const updatePayload: Partial<OrganizationStaff> = { updated_by: userId };
    if (dto.status !== undefined) updatePayload.status = dto.status;
    if (dto.department !== undefined) updatePayload.department = dto.department;
    if (dto.position_title !== undefined) updatePayload.position_title = dto.position_title;
    if (Object.keys(updatePayload).length > 1) {
      await this.organizationStaffRepository.update(
        { organization_id: organizationId, user_id: staffUserId },
        updatePayload,
      );
    }

    await this.auditLogService.log({
      userId,
      action: 'UPDATE',
      resourceType: 'ORGANIZATION_STAFF',
      resourceId: staffUserId,
      description: 'Staff updated',
      metadata: { organization_id: organizationId, ...dto },
      ipAddress,
      userAgent,
      status: 'success',
    });

    return { message: 'Staff updated successfully.' };
  }

  /**
   * Assign an additional staff role to a user in this organization.
   */
  async assignRole(
    organizationId: string,
    staffUserId: string,
    staffRoleId: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ id: string; staff_role_id: string; name: string }> {
    const isOwner = await this.organizationRoleService.isOrganizationOwner(userId, organizationId);
    const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(userId, organizationId, ['OWNER', 'HR', 'MANAGER']);
    if (!isOwner && !hasRole) {
      throw new ForbiddenException('You do not have permission to assign roles.');
    }

    const staffRole = await this.staffRoleRepository.findOne({ where: { id: staffRoleId } });
    if (!staffRole) {
      throw new NotFoundException('Staff role not found.');
    }

    const existing = await this.organizationStaffRepository.findOne({
      where: { organization_id: organizationId, user_id: staffUserId, staff_role_id: staffRoleId },
    });
    if (existing) {
      throw new ConflictException('This staff member already has this role.');
    }

    const anyRow = await this.organizationStaffRepository.findOne({
      where: { organization_id: organizationId, user_id: staffUserId },
    });
    if (!anyRow) {
      throw new NotFoundException('Staff member not found in this organization.');
    }

    const row = this.organizationStaffRepository.create({
      organization_id: organizationId,
      user_id: staffUserId,
      staff_role_id: staffRoleId,
      status: anyRow.status,
      department: anyRow.department,
      position_title: anyRow.position_title,
      created_by: userId,
      updated_by: userId,
    });
    const saved = await this.organizationStaffRepository.save(row);

    await this.auditLogService.log({
      userId,
      action: 'CREATE',
      resourceType: 'ORGANIZATION_STAFF',
      resourceId: saved.id,
      description: 'Staff role assigned',
      metadata: { organization_id: organizationId, user_id: staffUserId, staff_role_id: staffRoleId },
      ipAddress,
      userAgent,
      status: 'success',
    });

    return { id: saved.id, staff_role_id: staffRole.id, name: staffRole.name };
  }

  /**
   * Remove a staff role from a user in this organization.
   */
  async removeRole(
    organizationId: string,
    staffUserId: string,
    staffRoleId: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    const isOwner = await this.organizationRoleService.isOrganizationOwner(userId, organizationId);
    const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(userId, organizationId, ['OWNER', 'HR', 'MANAGER']);
    if (!isOwner && !hasRole) {
      throw new ForbiddenException('You do not have permission to remove roles.');
    }

    const row = await this.organizationStaffRepository.findOne({
      where: { organization_id: organizationId, user_id: staffUserId, staff_role_id: staffRoleId },
    });
    if (!row) {
      throw new NotFoundException('Staff role assignment not found.');
    }

    const count = await this.organizationStaffRepository.count({
      where: { organization_id: organizationId, user_id: staffUserId },
    });
    if (count <= 1) {
      throw new BadRequestException('Cannot remove the only role. Update status or add another role first.');
    }

    await this.organizationStaffRepository.remove(row);

    await this.auditLogService.log({
      userId,
      action: 'DELETE',
      resourceType: 'ORGANIZATION_STAFF',
      resourceId: row.id,
      description: 'Staff role removed',
      metadata: { organization_id: organizationId, user_id: staffUserId, staff_role_id: staffRoleId },
      ipAddress,
      userAgent,
      status: 'success',
    });

    return { message: 'Role removed successfully.' };
  }
}
