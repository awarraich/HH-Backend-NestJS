import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { LabWorkstation } from '../entities/lab-workstation.entity';
import { WorkstationShiftAssignment } from '../entities/workstation-shift-assignment.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateLabWorkstationDto } from '../dto/create-lab-workstation.dto';
import { UpdateLabWorkstationDto } from '../dto/update-lab-workstation.dto';
import { QueryLabWorkstationDto } from '../dto/query-lab-workstation.dto';

@Injectable()
export class LabWorkstationService {
  constructor(
    @InjectRepository(LabWorkstation)
    private readonly workstationRepository: Repository<LabWorkstation>,
    @InjectRepository(WorkstationShiftAssignment)
    private readonly wsaRepository: Repository<WorkstationShiftAssignment>,
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
    query: QueryLabWorkstationDto,
    userId: string,
  ): Promise<{ data: LabWorkstation[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const { page = 1, limit = 50, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.workstationRepository
      .createQueryBuilder('w')
      .leftJoinAndSelect('w.shiftAssignments', 'sa')
      .where('w.department_id = :departmentId', { departmentId });

    if (is_active !== undefined) {
      qb.andWhere('w.is_active = :is_active', { is_active });
    }
    qb.orderBy('w.sort_order', 'ASC', 'NULLS LAST').addOrderBy('w.name', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    workstationId: string,
    userId: string,
  ): Promise<LabWorkstation> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const ws = await this.workstationRepository.findOne({
      where: { id: workstationId, department_id: departmentId },
      relations: ['shiftAssignments'],
    });
    if (!ws) throw new NotFoundException('Lab workstation not found');
    return ws;
  }

  async create(
    organizationId: string,
    departmentId: string,
    dto: CreateLabWorkstationDto,
    userId: string,
  ): Promise<LabWorkstation> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const ws = await this.workstationRepository.save(
      this.workstationRepository.create({
        department_id: departmentId,
        name: dto.name,
        equipment: dto.equipment ?? null,
        workstation_type: dto.workstation_type ?? null,
        is_active: dto.is_active ?? true,
        sort_order: dto.sort_order ?? null,
      }),
    );
    if (dto.shift_ids?.length) {
      await this.syncShiftAssignments(ws.id, dto.shift_ids);
    }
    return this.findOne(organizationId, departmentId, ws.id, userId);
  }

  async update(
    organizationId: string,
    departmentId: string,
    workstationId: string,
    dto: UpdateLabWorkstationDto,
    userId: string,
  ): Promise<LabWorkstation> {
    await this.ensureAccess(organizationId, userId);
    const ws = await this.findOne(organizationId, departmentId, workstationId, userId);
    if (dto.name !== undefined) ws.name = dto.name;
    if (dto.equipment !== undefined) ws.equipment = dto.equipment;
    if (dto.workstation_type !== undefined) ws.workstation_type = dto.workstation_type;
    if (dto.is_active !== undefined) ws.is_active = dto.is_active;
    if (dto.sort_order !== undefined) ws.sort_order = dto.sort_order;
    await this.workstationRepository.save(ws);
    if (dto.shift_ids !== undefined) {
      await this.syncShiftAssignments(workstationId, dto.shift_ids);
    }
    return this.findOne(organizationId, departmentId, workstationId, userId);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    workstationId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const ws = await this.findOne(organizationId, departmentId, workstationId, userId);
    await this.workstationRepository.remove(ws);
  }

  private async syncShiftAssignments(workstationId: string, shiftIds: string[]): Promise<void> {
    await this.wsaRepository.delete({ workstation_id: workstationId });
    if (shiftIds.length) {
      const assignments = shiftIds.map((shift_id) =>
        this.wsaRepository.create({ workstation_id: workstationId, shift_id }),
      );
      await this.wsaRepository.save(assignments);
    }
  }
}
