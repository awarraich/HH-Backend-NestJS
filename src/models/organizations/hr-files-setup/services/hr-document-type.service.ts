import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { HrDocumentType } from '../entities/hr-document-type.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateHrDocumentTypeDto } from '../dto/create-hr-document-type.dto';
import { UpdateHrDocumentTypeDto } from '../dto/update-hr-document-type.dto';
import { QueryHrDocumentTypeDto } from '../dto/query-hr-document-type.dto';

@Injectable()
export class HrDocumentTypeService {
  constructor(
    @InjectRepository(HrDocumentType)
    private readonly hrDocumentTypeRepository: Repository<HrDocumentType>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    private readonly organizationRoleService: OrganizationRoleService,
  ) {}

  private async ensureAccess(organizationId: string, userId: string): Promise<void> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(
      userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (!canAccess) {
      throw new ForbiddenException(
        'You do not have permission to manage HR document types in this organization.',
      );
    }

    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }
  }

  async findAll(
    organizationId: string,
    queryDto: QueryHrDocumentTypeDto,
    userId: string,
  ): Promise<{ data: HrDocumentType[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);

    const {
      page = 1,
      limit = 20,
      category,
      is_required,
      is_active = true,
      search,
    } = queryDto;
    const skip = (page - 1) * limit;

    const qb = this.hrDocumentTypeRepository
      .createQueryBuilder('hdt')
      .where('hdt.organization_id = :organizationId', { organizationId })
      .andWhere('hdt.employee_id IS NULL');

    if (category !== undefined && category !== '') {
      qb.andWhere('hdt.category = :category', { category });
    }
    if (is_required !== undefined) {
      qb.andWhere('hdt.is_required = :is_required', { is_required });
    }
    if (is_active !== undefined) {
      qb.andWhere('hdt.is_active = :is_active', { is_active });
    }
    if (search && search.trim()) {
      qb.andWhere(
        '(hdt.code ILIKE :search OR hdt.name ILIKE :search)',
        { search: `%${search.trim()}%` },
      );
    }

    qb.orderBy('hdt.sort_order', 'ASC').addOrderBy('hdt.id', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();

    return { data, total, page, limit };
  }

  async create(
    organizationId: string,
    dto: CreateHrDocumentTypeDto,
    userId: string,
  ): Promise<HrDocumentType> {
    await this.ensureAccess(organizationId, userId);

    const existing = await this.hrDocumentTypeRepository.findOne({
      where: { organization_id: organizationId, code: dto.code, employee_id: IsNull() },
    });
    if (existing) {
      throw new ConflictException(
        `A document type with code "${dto.code}" already exists for this organization.`,
      );
    }

    const entity = this.hrDocumentTypeRepository.create({
      organization_id: organizationId,
      code: dto.code,
      name: dto.name,
      has_expiration: dto.has_expiration ?? false,
      is_required: dto.is_required ?? false,
      category: dto.category ?? null,
      sort_order: dto.sort_order ?? 0,
      is_active: true,
    });

    return this.hrDocumentTypeRepository.save(entity);
  }

  async update(
    organizationId: string,
    id: string,
    dto: UpdateHrDocumentTypeDto,
    userId: string,
  ): Promise<HrDocumentType> {
    await this.ensureAccess(organizationId, userId);

    const entity = await this.hrDocumentTypeRepository.findOne({
      where: { id, organization_id: organizationId, employee_id: IsNull() },
    });
    if (!entity) {
      throw new NotFoundException('HR document type not found');
    }

    if (dto.name !== undefined) entity.name = dto.name;
    if (dto.has_expiration !== undefined) entity.has_expiration = dto.has_expiration;
    if (dto.is_required !== undefined) entity.is_required = dto.is_required;
    if (dto.category !== undefined) entity.category = dto.category;
    if (dto.sort_order !== undefined) entity.sort_order = dto.sort_order;
    if (dto.is_active !== undefined) entity.is_active = dto.is_active;

    return this.hrDocumentTypeRepository.save(entity);
  }

  async remove(organizationId: string, id: string, userId: string): Promise<void> {
    await this.ensureAccess(organizationId, userId);

    const entity = await this.hrDocumentTypeRepository.findOne({
      where: { id, organization_id: organizationId, employee_id: IsNull() },
    });
    if (!entity) {
      throw new NotFoundException('HR document type not found');
    }

    entity.is_active = false;
    await this.hrDocumentTypeRepository.save(entity);
  }

  async toggleRequired(
    organizationId: string,
    id: string,
    userId: string,
  ): Promise<HrDocumentType> {
    await this.ensureAccess(organizationId, userId);

    const entity = await this.hrDocumentTypeRepository.findOne({
      where: { id, organization_id: organizationId, employee_id: IsNull() },
    });
    if (!entity) {
      throw new NotFoundException('HR document type not found');
    }

    entity.is_required = !entity.is_required;
    return this.hrDocumentTypeRepository.save(entity);
  }
}
