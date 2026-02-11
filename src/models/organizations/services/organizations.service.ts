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
import { Organization } from '../entities/organization.entity';
import { OrganizationProfile } from '../entities/organization-profile.entity';
import { OrganizationTypeAssignment } from '../entities/organization-type-assignment.entity';
import { OrganizationType } from '../entities/organization-type.entity';
import { OrganizationRepository } from '../repositories/organization.repository';
import { CreateOrganizationDto } from '../dto/create-organization.dto';
import { UpdateOrganizationDto } from '../dto/update-organization.dto';
import { QueryOrganizationDto } from '../dto/query-organization.dto';
import { CreateOrganizationProfileDto } from '../dto/create-organization-profile.dto';
import { UpdateOrganizationProfileDto } from '../dto/update-organization-profile.dto';
import { AssignOrganizationTypeDto } from '../dto/assign-organization-type.dto';
import { UpdateOrganizationPermissionDto } from '../dto/update-organization-permission.dto';
import { QueryReferralOrganizationsDto } from '../dto/query-referral-organizations.dto';
import { OrganizationSerializer } from '../serializers/organization.serializer';
import { AuditLogService } from '../../../common/services/audit/audit-log.service';
import { OrganizationPermissionService } from './organization-permission.service';

@Injectable()
export class OrganizationsService {
  private readonly logger = new Logger(OrganizationsService.name);
  private organizationSerializer = new OrganizationSerializer();

  constructor(
    private organizationRepository: OrganizationRepository,
    @InjectRepository(OrganizationProfile)
    private organizationProfileRepository: Repository<OrganizationProfile>,
    @InjectRepository(OrganizationTypeAssignment)
    private organizationTypeAssignmentRepository: Repository<OrganizationTypeAssignment>,
    @InjectRepository(OrganizationType)
    private organizationTypeRepository: Repository<OrganizationType>,
    private dataSource: DataSource,
    private auditLogService: AuditLogService,
    private organizationPermissionService: OrganizationPermissionService,
  ) {}

  async create(
    createDto: CreateOrganizationDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    // Check if user already has an organization
    const existingOrg = await this.organizationRepository.findByUserId(userId);
    if (existingOrg) {
      throw new ConflictException('User already has an organization');
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const organization = this.organizationRepository.create({
        user_id: userId,
        organization_name: createDto.organization_name,
        tax_id: createDto.tax_id,
        registration_number: createDto.registration_number,
        website: createDto.website,
        description: createDto.description,
      });

      const saved = await queryRunner.manager.save(Organization, organization);

      await queryRunner.commitTransaction();

      // HIPAA Compliance: Log operation
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'ORGANIZATION',
          resourceId: saved.id,
          description: 'Organization created',
          metadata: { organization_name: saved.organization_name },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (error) {
        this.logger.error('Failed to log audit event', error);
      }

      this.logger.log(`Organization created: ${saved.id} by user: ${userId}`);

      return this.organizationSerializer.serialize(saved);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to create organization', error);

      // Log failure
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'ORGANIZATION',
          description: 'Failed to create organization',
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

  async findAll(queryDto: QueryOrganizationDto): Promise<{
    data: any[];
    total: number;
    page: number;
    limit: number;
  }> {
    const { search, page = 1, limit = 20 } = queryDto;
    const skip = (page - 1) * limit;

    const queryBuilder = this.organizationRepository.createQueryBuilder('organization');

    if (search) {
      queryBuilder.where(
        '(organization.organization_name ILIKE :search OR organization.tax_id ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    queryBuilder.orderBy('organization.created_at', 'DESC');
    queryBuilder.skip(skip).take(limit);

    const [organizations, total] = await queryBuilder.getManyAndCount();

    return {
      data: this.organizationSerializer.serializeMany(organizations),
      total,
      page,
      limit,
    };
  }

  async findOne(id: string): Promise<any> {
    const organization = await this.organizationRepository.findByIdWithRelations(id);

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    return this.organizationSerializer.serialize(organization);
  }

  async findMyOrganization(userId: string): Promise<any> {
    const organization = await this.organizationRepository.findByUserId(userId);

    if (!organization) {
      throw new NotFoundException('You do not have an organization');
    }

    return this.organizationSerializer.serialize(organization);
  }

  async findForReferralSelection(
    query: QueryReferralOrganizationsDto,
  ): Promise<{ id: string; organization_name: string; organization_type: string }[]> {
    const page = query.page ?? 1;
    const pageSize = query.page_size ?? 50;
    const qb = this.organizationRepository
      .createQueryBuilder('org')
      .innerJoin('org.typeAssignments', 'ta')
      .innerJoin('ta.organizationType', 'ot')
      .select('org.id', 'id')
      .addSelect('org.organization_name', 'organization_name')
      .addSelect('MIN(ot.name)', 'organization_type')
      .groupBy('org.id')
      .addGroupBy('org.organization_name')
      .orderBy('org.organization_name', 'ASC')
      .offset((page - 1) * pageSize)
      .limit(pageSize);

    if (query.search?.trim()) {
      qb.andWhere('org.organization_name ILIKE :search', {
        search: `%${query.search.trim()}%`,
      });
    }
    if (query.organization_type?.trim()) {
      const typeParam = query.organization_type.trim();
      if (/^\d+$/.test(typeParam)) {
        qb.andWhere('ot.id = :typeId', { typeId: parseInt(typeParam, 10) });
      } else {
        qb.andWhere('ot.name = :typeName', { typeName: typeParam });
      }
    }
    if (query.exclude_organization_id) {
      qb.andWhere('org.id != :excludeOrganizationId', {
        excludeOrganizationId: query.exclude_organization_id,
      });
    }

    const raw = await qb.getRawMany<{ id: string; organization_name: string; organization_type: string }>();
    return raw.map((r) => ({
      id: r.id,
      organization_name: r.organization_name ?? '',
      organization_type: r.organization_type ?? '',
    }));
  }

  async update(
    id: string,
    updateDto: UpdateOrganizationDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    // Validate ownership
    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'ORGANIZATION',
          resourceId: id,
          description: 'Unauthorized update attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update this organization');
    }

    const beforeValues = { ...organization };

    Object.assign(organization, updateDto);
    const updated = await this.organizationRepository.save(organization);

    // HIPAA Compliance: Log operation with before/after values
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'ORGANIZATION',
        resourceId: id,
        description: 'Organization updated',
        metadata: {
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

    this.logger.log(`Organization updated: ${id} by user: ${userId}`);

    return this.organizationSerializer.serialize(updated);
  }

  async delete(
    id: string,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    // Validate ownership
    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'ORGANIZATION',
          resourceId: id,
          description: 'Unauthorized delete attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to delete this organization');
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      await queryRunner.manager.remove(Organization, organization);
      await queryRunner.commitTransaction();

      // HIPAA Compliance: Log operation
      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'ORGANIZATION',
          resourceId: id,
          description: 'Organization deleted',
          metadata: { organization_name: organization.organization_name },
          ipAddress,
          userAgent,
          status: 'success',
        });
      } catch (error) {
        this.logger.error('Failed to log audit event', error);
      }

      this.logger.log(`Organization deleted: ${id} by user: ${userId}`);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error('Failed to delete organization', error);

      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'ORGANIZATION',
          resourceId: id,
          description: 'Failed to delete organization',
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

  async createProfile(
    id: string,
    createDto: CreateOrganizationProfileDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const organization = await this.organizationRepository.findOne({
      where: { id },
    });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'CREATE',
          resourceType: 'ORGANIZATION_PROFILE',
          resourceId: id,
          description: 'Unauthorized profile creation attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException(
        'You do not have permission to create this organization profile',
      );
    }

    const existingProfile = await this.organizationProfileRepository.findOne({
      where: { organization_id: id },
    });

    if (existingProfile) {
      throw new ConflictException(
        'Organization profile already exists. Use update endpoint instead.',
      );
    }

    const existingAssignment = await this.organizationTypeAssignmentRepository.findOne({
      where: { organization_id: id },
    });

    if (!existingAssignment) {
      throw new BadRequestException(
        'Organization must have at least one type assigned before creating a profile',
      );
    }

    const profile = this.organizationProfileRepository.create({
      organization_id: id,
      organization_type_id: existingAssignment.organization_type_id,
      ...createDto,
    });

    const saved = await this.organizationProfileRepository.save(profile);

    try {
      await this.auditLogService.log({
        userId,
        action: 'CREATE',
        resourceType: 'ORGANIZATION_PROFILE',
        resourceId: id,
        description: 'Organization profile created',
        metadata: {
          profile: saved,
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(`Organization profile created: ${id} by user: ${userId}`);

    const organizationWithProfile =
      await this.organizationRepository.findByIdWithRelations(id);
    if (!organizationWithProfile) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    return this.organizationSerializer.serialize(organizationWithProfile).profile;
  }

  async updateProfile(
    id: string,
    profileDto: UpdateOrganizationProfileDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    // Validate ownership
    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'ORGANIZATION_PROFILE',
          resourceId: id,
          description: 'Unauthorized profile update attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update this organization profile');
    }

    let profile = await this.organizationProfileRepository.findOne({
      where: { organization_id: id },
    });

    const beforeValues = profile ? { ...profile } : null;

    if (!profile) {
      // Create profile if it doesn't exist - need to get organization type from existing assignment or default
      const existingAssignment = await this.organizationTypeAssignmentRepository.findOne({
        where: { organization_id: id },
      });
      
      profile = this.organizationProfileRepository.create({
        organization_id: id,
        organization_type_id: existingAssignment?.organization_type_id || 1, // Default type if not provided
      });
    }

    Object.assign(profile, profileDto);
    const updated = await this.organizationProfileRepository.save(profile);

    // HIPAA Compliance: Log operation
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'ORGANIZATION_PROFILE',
        resourceId: id,
        description: 'Organization profile updated',
        metadata: {
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

    this.logger.log(`Organization profile updated: ${id} by user: ${userId}`);

    const organizationWithProfile = await this.organizationRepository.findByIdWithRelations(id);
    if (!organizationWithProfile) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }
    return this.organizationSerializer.serialize(organizationWithProfile).profile;
  }

  async assignType(
    id: string,
    assignDto: AssignOrganizationTypeDto,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    // Validate ownership
    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'ORGANIZATION',
          resourceId: id,
          description: 'Unauthorized type assignment attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to assign types to this organization');
    }

    // Check if type exists
    const orgType = await this.organizationTypeRepository.findOne({
      where: { id: assignDto.organization_type_id },
    });

    if (!orgType) {
      throw new NotFoundException(`Organization type with ID ${assignDto.organization_type_id} not found`);
    }

    // Check if assignment already exists
    const existing = await this.organizationTypeAssignmentRepository.findOne({
      where: {
        organization_id: id,
        organization_type_id: assignDto.organization_type_id,
      },
    });

    if (existing) {
      throw new ConflictException('Organization type is already assigned');
    }

    const assignment = this.organizationTypeAssignmentRepository.create({
      organization_id: id,
      organization_type_id: assignDto.organization_type_id,
    });

    await this.organizationTypeAssignmentRepository.save(assignment);

    // HIPAA Compliance: Log operation
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'ORGANIZATION',
        resourceId: id,
        description: 'Organization type assigned',
        metadata: {
          organization_type_id: assignDto.organization_type_id,
          organization_type_name: orgType.name,
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(`Organization type assigned: ${id} type: ${assignDto.organization_type_id} by user: ${userId}`);

    const organizationWithTypes = await this.organizationRepository.findByIdWithRelations(id);
    if (!organizationWithTypes) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }
    return this.organizationSerializer.serialize(organizationWithTypes);
  }

  async removeType(
    id: string,
    typeId: number,
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    // Validate ownership
    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'DELETE',
          resourceType: 'ORGANIZATION_TYPE_ASSIGNMENT',
          resourceId: id,
          description: 'Unauthorized type removal attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to remove types from this organization');
    }

    const assignment = await this.organizationTypeAssignmentRepository.findOne({
      where: {
        organization_id: id,
        organization_type_id: typeId,
      },
    });

    if (!assignment) {
      throw new NotFoundException('Organization type assignment not found');
    }

    await this.organizationTypeAssignmentRepository.remove(assignment);

    // HIPAA Compliance: Log operation
    try {
      await this.auditLogService.log({
        userId,
        action: 'DELETE',
        resourceType: 'ORGANIZATION_TYPE_ASSIGNMENT',
        resourceId: id,
        description: 'Organization type removed',
        metadata: { organization_type_id: typeId },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(`Organization type removed: ${id} type: ${typeId} by user: ${userId}`);
  }

  async getPermissions(id: string): Promise<any> {
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    const permissions = await this.organizationPermissionService.getOrganizationPermissions(id);

    return permissions.map((perm) => ({
      id: perm.id,
      role: perm.role,
      feature: perm.feature,
      has_access: perm.has_access,
      created_at: perm.created_at,
      updated_at: perm.updated_at,
    }));
  }

  async updatePermissions(
    id: string,
    permissionsDto: UpdateOrganizationPermissionDto | UpdateOrganizationPermissionDto[],
    userId: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    const permissionsArray = Array.isArray(permissionsDto) ? permissionsDto : [permissionsDto];
    const organization = await this.organizationRepository.findOne({ where: { id } });

    if (!organization) {
      throw new NotFoundException(`Organization with ID ${id} not found`);
    }

    // Validate ownership
    if (organization.user_id !== userId) {
      try {
        await this.auditLogService.log({
          userId,
          action: 'UPDATE',
          resourceType: 'ORGANIZATION_PERMISSIONS',
          resourceId: id,
          description: 'Unauthorized permissions update attempt',
          ipAddress,
          userAgent,
          status: 'failure',
          errorMessage: 'User is not organization owner',
        });
      } catch (logError) {
        this.logger.error('Failed to log audit error', logError);
      }

      throw new ForbiddenException('You do not have permission to update permissions for this organization');
    }

    const beforePermissions = await this.organizationPermissionService.getOrganizationPermissions(id);

    // Update each permission
    for (const permDto of permissionsArray) {
      await this.organizationPermissionService.updatePermission(
        id,
        permDto.role,
        permDto.feature,
        permDto.hasAccess,
      );
    }

    const afterPermissions = await this.organizationPermissionService.getOrganizationPermissions(id);

    // HIPAA Compliance: Log operation
    try {
      await this.auditLogService.log({
        userId,
        action: 'UPDATE',
        resourceType: 'ORGANIZATION_PERMISSIONS',
        resourceId: id,
        description: 'Organization permissions updated',
        metadata: {
          before: beforePermissions,
          after: afterPermissions,
        },
        ipAddress,
        userAgent,
        status: 'success',
      });
    } catch (error) {
      this.logger.error('Failed to log audit event', error);
    }

    this.logger.log(`Organization permissions updated: ${id} by user: ${userId}`);

    return this.getPermissions(id);
  }
}

