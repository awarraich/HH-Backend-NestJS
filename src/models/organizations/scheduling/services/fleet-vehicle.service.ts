import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { FleetVehicle } from '../entities/fleet-vehicle.entity';
import { VehicleShiftAssignment } from '../entities/vehicle-shift-assignment.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateFleetVehicleDto } from '../dto/create-fleet-vehicle.dto';
import { UpdateFleetVehicleDto } from '../dto/update-fleet-vehicle.dto';
import { QueryFleetVehicleDto } from '../dto/query-fleet-vehicle.dto';

@Injectable()
export class FleetVehicleService {
  constructor(
    @InjectRepository(FleetVehicle)
    private readonly vehicleRepository: Repository<FleetVehicle>,
    @InjectRepository(VehicleShiftAssignment)
    private readonly vsaRepository: Repository<VehicleShiftAssignment>,
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
    query: QueryFleetVehicleDto,
    userId: string,
  ): Promise<{ data: FleetVehicle[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const { page = 1, limit = 50, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.vehicleRepository
      .createQueryBuilder('v')
      .leftJoinAndSelect('v.shiftAssignments', 'sa')
      .where('v.department_id = :departmentId', { departmentId });

    if (is_active !== undefined) {
      qb.andWhere('v.is_active = :is_active', { is_active });
    }
    qb.orderBy('v.sort_order', 'ASC', 'NULLS LAST').addOrderBy('v.name', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    vehicleId: string,
    userId: string,
  ): Promise<FleetVehicle> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const vehicle = await this.vehicleRepository.findOne({
      where: { id: vehicleId, department_id: departmentId },
      relations: ['shiftAssignments'],
    });
    if (!vehicle) throw new NotFoundException('Fleet vehicle not found');
    return vehicle;
  }

  async create(
    organizationId: string,
    departmentId: string,
    dto: CreateFleetVehicleDto,
    userId: string,
  ): Promise<FleetVehicle> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureDepartment(organizationId, departmentId);
    const vehicle = await this.vehicleRepository.save(
      this.vehicleRepository.create({
        department_id: departmentId,
        name: dto.name,
        vehicle_id: dto.vehicle_id ?? null,
        vehicle_type: dto.vehicle_type ?? null,
        capacity: dto.capacity ?? 0,
        is_active: dto.is_active ?? true,
        sort_order: dto.sort_order ?? null,
      }),
    );
    if (dto.shift_ids?.length) {
      await this.syncShiftAssignments(vehicle.id, dto.shift_ids);
    }
    return this.findOne(organizationId, departmentId, vehicle.id, userId);
  }

  async update(
    organizationId: string,
    departmentId: string,
    vehicleId: string,
    dto: UpdateFleetVehicleDto,
    userId: string,
  ): Promise<FleetVehicle> {
    await this.ensureAccess(organizationId, userId);
    const vehicle = await this.findOne(organizationId, departmentId, vehicleId, userId);
    if (dto.name !== undefined) vehicle.name = dto.name;
    if (dto.vehicle_id !== undefined) vehicle.vehicle_id = dto.vehicle_id;
    if (dto.vehicle_type !== undefined) vehicle.vehicle_type = dto.vehicle_type;
    if (dto.capacity !== undefined) vehicle.capacity = dto.capacity;
    if (dto.is_active !== undefined) vehicle.is_active = dto.is_active;
    if (dto.sort_order !== undefined) vehicle.sort_order = dto.sort_order;
    await this.vehicleRepository.save(vehicle);
    if (dto.shift_ids !== undefined) {
      await this.syncShiftAssignments(vehicleId, dto.shift_ids);
    }
    return this.findOne(organizationId, departmentId, vehicleId, userId);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    vehicleId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const vehicle = await this.findOne(organizationId, departmentId, vehicleId, userId);
    await this.vehicleRepository.remove(vehicle);
  }

  private async syncShiftAssignments(vehicleId: string, shiftIds: string[]): Promise<void> {
    await this.vsaRepository.delete({ vehicle_id: vehicleId });
    if (shiftIds.length) {
      const assignments = shiftIds.map((shift_id) =>
        this.vsaRepository.create({ vehicle_id: vehicleId, shift_id }),
      );
      await this.vsaRepository.save(assignments);
    }
  }
}
