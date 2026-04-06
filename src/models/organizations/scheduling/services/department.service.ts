import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { Room } from '../entities/room.entity';
import { Bed } from '../entities/bed.entity';
import { Chair } from '../entities/chair.entity';
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
    @InjectRepository(Station)
    private readonly stationRepository: Repository<Station>,
    @InjectRepository(Room)
    private readonly roomRepository: Repository<Room>,
    @InjectRepository(Bed)
    private readonly bedRepository: Repository<Bed>,
    @InjectRepository(Chair)
    private readonly chairRepository: Repository<Chair>,
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

  async create(
    organizationId: string,
    dto: CreateDepartmentDto,
    userId: string,
  ): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = this.departmentRepository.create({
      organization_id: organizationId,
      name: dto.name,
      code: dto.code ?? null,
      description: dto.description ?? null,
      department_type: dto.department_type ?? null,
      layout_type: dto.layout_type ?? null,
      is_active: dto.is_active ?? true,
      sort_order: dto.sort_order ?? null,
    });
    const saved = await this.departmentRepository.save(department);

    // Bulk create stations (for 'stations' layout)
    if (dto.stations?.length) {
      for (let si = 0; si < dto.stations.length; si++) {
        const s = dto.stations[si];
        const station = await this.stationRepository.save(
          this.stationRepository.create({
            department_id: saved.id,
            name: s.name,
            location: s.location ?? null,
            multi_station_am: s.multi_station_am ?? false,
            multi_station_pm: s.multi_station_pm ?? false,
            multi_station_noc: s.multi_station_noc ?? false,
            custom_shift_times: s.custom_shift_times ?? null,
            configuration_type: s.configuration_type ?? null,
            default_beds_per_room: s.default_beds_per_room ?? null,
            default_chairs_per_room: s.default_chairs_per_room ?? null,
            is_active: true,
            sort_order: si,
          }),
        );
        if (s.rooms?.length) {
          const configType = s.configuration_type ?? 'BEDS';
          for (let ri = 0; ri < s.rooms.length; ri++) {
            const r = s.rooms[ri];
            const bedsCount = configType === 'BEDS' ? (r.beds ?? s.default_beds_per_room ?? 0) : 0;
            const chairsCount = configType === 'CHAIRS' ? (r.chairs ?? s.default_chairs_per_room ?? 0) : 0;
            const room = await this.roomRepository.save(
              this.roomRepository.create({
                station_id: station.id,
                name: r.name,
                configuration_type: configType,
                beds_per_room: bedsCount || null,
                chairs_per_room: chairsCount || null,
                is_active: true,
                sort_order: ri,
              }),
            );
            for (let b = 0; b < bedsCount; b++) {
              await this.bedRepository.save(
                this.bedRepository.create({ room_id: room.id, bed_number: String(b + 1) }),
              );
            }
            for (let c = 0; c < chairsCount; c++) {
              await this.chairRepository.save(
                this.chairRepository.create({ room_id: room.id, chair_number: String(c + 1) }),
              );
            }
          }
        }
      }
    }

    // Bulk create rooms (for 'rooms' layout — creates a default station to hold them)
    if (dto.rooms?.length) {
      const defaultStation = await this.stationRepository.save(
        this.stationRepository.create({
          department_id: saved.id,
          name: `${dto.name} - Default`,
          is_active: true,
          sort_order: 0,
        }),
      );
      for (let ri = 0; ri < dto.rooms.length; ri++) {
        const r = dto.rooms[ri];
        const bedsCount = r.beds ?? 0;
        const chairsCount = r.chairs ?? 0;
        const room = await this.roomRepository.save(
          this.roomRepository.create({
            station_id: defaultStation.id,
            name: r.name,
            room_type: r.room_type ?? null,
            configuration_type: bedsCount > 0 ? 'BEDS' : chairsCount > 0 ? 'CHAIRS' : null,
            beds_per_room: bedsCount || null,
            chairs_per_room: chairsCount || null,
            is_active: true,
            sort_order: ri,
          }),
        );
        for (let b = 0; b < bedsCount; b++) {
          await this.bedRepository.save(
            this.bedRepository.create({ room_id: room.id, bed_number: String(b + 1) }),
          );
        }
        for (let c = 0; c < chairsCount; c++) {
          await this.chairRepository.save(
            this.chairRepository.create({ room_id: room.id, chair_number: String(c + 1) }),
          );
        }
      }
    }

    return saved;
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
    if (dto.layout_type !== undefined) department.layout_type = dto.layout_type;
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
