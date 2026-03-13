import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateStationDto } from '../dto/create-station.dto';
import { UpdateStationDto } from '../dto/update-station.dto';
import { QueryStationDto } from '../dto/query-station.dto';

@Injectable()
export class StationService {
  constructor(
    @InjectRepository(Station)
    private readonly stationRepository: Repository<Station>,
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

  private async ensureDepartmentInOrg(
    organizationId: string,
    departmentId: string,
  ): Promise<Department> {
    const department = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!department) throw new NotFoundException('Department not found');
    return department;
  }

  async findAll(
    organizationId: string,
    departmentId: string,
    query: QueryStationDto,
    userId: string,
  ): Promise<{ data: Station[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartmentInOrg(organizationId, departmentId);
    const { page = 1, limit = 20, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.stationRepository
      .createQueryBuilder('s')
      .where('s.department_id = :departmentId', { departmentId });

    if (is_active !== undefined) {
      qb.andWhere('s.is_active = :is_active', { is_active });
    }
    qb.orderBy('s.sort_order', 'ASC', 'NULLS LAST').addOrderBy('s.name', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    stationId: string,
    userId: string,
  ): Promise<Station> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartmentInOrg(organizationId, departmentId);
    const station = await this.stationRepository.findOne({
      where: { id: stationId, department_id: departmentId },
    });
    if (!station) throw new NotFoundException('Station not found');
    return station;
  }

  async create(
    organizationId: string,
    departmentId: string,
    dto: CreateStationDto,
    userId: string,
  ): Promise<Station> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartmentInOrg(organizationId, departmentId);
    const station = this.stationRepository.create({
      department_id: departmentId,
      name: dto.name,
      code: dto.code ?? null,
      is_active: dto.is_active ?? true,
      sort_order: dto.sort_order ?? null,
    });
    return this.stationRepository.save(station);
  }

  async update(
    organizationId: string,
    departmentId: string,
    stationId: string,
    dto: UpdateStationDto,
    userId: string,
  ): Promise<Station> {
    await this.ensureAccess(organizationId, userId);
    const station = await this.findOne(organizationId, departmentId, stationId, userId);
    if (dto.name !== undefined) station.name = dto.name;
    if (dto.code !== undefined) station.code = dto.code;
    if (dto.is_active !== undefined) station.is_active = dto.is_active;
    if (dto.sort_order !== undefined) station.sort_order = dto.sort_order;
    return this.stationRepository.save(station);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    stationId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const station = await this.findOne(organizationId, departmentId, stationId, userId);
    await this.stationRepository.remove(station);
  }
}
