import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateDepartmentDto } from '../dto/create-department.dto';
import { UpdateDepartmentDto } from '../dto/update-department.dto';
import { QueryDepartmentDto } from '../dto/query-department.dto';

@Injectable()
export class DepartmentService {
  constructor(
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
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
    if (!canAccess) throw new ForbiddenException('No access to this organization.');
    const org = await this.organizationRepository.findOne({ where: { id: organizationId } });
    if (!org) throw new NotFoundException('Organization not found');
  }

  async findAll(
    organizationId: string,
    query: QueryDepartmentDto,
    userId: string,
  ): Promise<{ data: Department[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    const { page = 1, limit = 20, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.departmentRepository
      .createQueryBuilder('d')
      .loadRelationCountAndMap('d.stationCount', 'd.stations')
      .where('d.organization_id = :organizationId', { organizationId });

    if (is_active !== undefined) {
      qb.andWhere('d.is_active = :is_active', { is_active });
    }
    qb.orderBy('d.sort_order', 'ASC', 'NULLS LAST').addOrderBy('d.name', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(organizationId: string, departmentId: string, userId: string): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!department) throw new NotFoundException('Department not found');
    return department;
  }

  async create(organizationId: string, dto: CreateDepartmentDto, userId: string): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = this.departmentRepository.create({
      organization_id: organizationId,
      name: dto.name,
      code: dto.code ?? null,
      description: dto.description ?? null,
      department_type: dto.department_type ?? null,
      is_active: dto.is_active ?? true,
      sort_order: dto.sort_order ?? null,
    });
    return this.departmentRepository.save(department);
  }

  async update(
    organizationId: string,
    departmentId: string,
    dto: UpdateDepartmentDto,
    userId: string,
  ): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.findOne(organizationId, departmentId, userId);
    if (dto.name !== undefined) department.name = dto.name;
    if (dto.code !== undefined) department.code = dto.code;
    if (dto.description !== undefined) department.description = dto.description;
    if (dto.department_type !== undefined) department.department_type = dto.department_type;
    if (dto.is_active !== undefined) department.is_active = dto.is_active;
    if (dto.sort_order !== undefined) department.sort_order = dto.sort_order;
    return this.departmentRepository.save(department);
  }

  async remove(organizationId: string, departmentId: string, userId: string): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.findOne(organizationId, departmentId, userId);
    await this.departmentRepository.remove(department);
  }
}
