import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { Zone } from '../entities/zone.entity';
import { ZoneShiftAssignment } from '../entities/zone-shift-assignment.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateZoneDto } from '../dto/create-zone.dto';
import { UpdateZoneDto } from '../dto/update-zone.dto';
import { QueryZoneDto } from '../dto/query-zone.dto';

@Injectable()
export class ZoneService {
  constructor(
    @InjectRepository(Zone)
    private readonly zoneRepository: Repository<Zone>,
    @InjectRepository(ZoneShiftAssignment)
    private readonly zsaRepository: Repository<ZoneShiftAssignment>,
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

  private async ensureDepartment(organizationId: string, departmentId: string): Promise<Department> {
    const dept = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!dept) throw new NotFoundException('Department not found');
    return dept;
  }

  async findAll(
    organizationId: string,
    departmentId: string,
    query: QueryZoneDto,
    userId: string,
  ): Promise<{ data: Zone[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const { page = 1, limit = 50, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.zoneRepository
      .createQueryBuilder('z')
      .leftJoinAndSelect('z.shiftAssignments', 'sa')
      .where('z.department_id = :departmentId', { departmentId });

    if (is_active !== undefined) {
      qb.andWhere('z.is_active = :is_active', { is_active });
    }
    qb.orderBy('z.sort_order', 'ASC', 'NULLS LAST').addOrderBy('z.name', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    zoneId: string,
    userId: string,
  ): Promise<Zone> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const zone = await this.zoneRepository.findOne({
      where: { id: zoneId, department_id: departmentId },
      relations: ['shiftAssignments'],
    });
    if (!zone) throw new NotFoundException('Zone not found');
    return zone;
  }

  async create(
    organizationId: string,
    departmentId: string,
    dto: CreateZoneDto,
    userId: string,
  ): Promise<Zone> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const zone = await this.zoneRepository.save(
      this.zoneRepository.create({
        department_id: departmentId,
        name: dto.name,
        area: dto.area ?? null,
        patient_count: dto.patient_count ?? 0,
        is_active: dto.is_active ?? true,
        sort_order: dto.sort_order ?? null,
      }),
    );
    if (dto.shift_ids?.length) {
      await this.syncShiftAssignments(zone.id, dto.shift_ids);
    }
    return this.findOne(organizationId, departmentId, zone.id, userId);
  }

  async update(
    organizationId: string,
    departmentId: string,
    zoneId: string,
    dto: UpdateZoneDto,
    userId: string,
  ): Promise<Zone> {
    await this.ensureAccess(organizationId, userId);
    const zone = await this.findOne(organizationId, departmentId, zoneId, userId);
    if (dto.name !== undefined) zone.name = dto.name;
    if (dto.area !== undefined) zone.area = dto.area;
    if (dto.patient_count !== undefined) zone.patient_count = dto.patient_count;
    if (dto.is_active !== undefined) zone.is_active = dto.is_active;
    if (dto.sort_order !== undefined) zone.sort_order = dto.sort_order;
    await this.zoneRepository.save(zone);
    if (dto.shift_ids !== undefined) {
      await this.syncShiftAssignments(zoneId, dto.shift_ids);
    }
    return this.findOne(organizationId, departmentId, zoneId, userId);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    zoneId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const zone = await this.findOne(organizationId, departmentId, zoneId, userId);
    await this.zoneRepository.remove(zone);
  }

  private async syncShiftAssignments(zoneId: string, shiftIds: string[]): Promise<void> {
    await this.zsaRepository.delete({ zone_id: zoneId });
    if (shiftIds.length) {
      const assignments = shiftIds.map((shift_id) =>
        this.zsaRepository.create({ zone_id: zoneId, shift_id }),
      );
      await this.zsaRepository.save(assignments);
    }
  }
}
