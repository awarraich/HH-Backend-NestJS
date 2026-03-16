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
      relations: ['rooms', 'rooms.beds', 'rooms.chairs'],
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
      location: dto.location ?? null,
      code: dto.code ?? null,
      required_charge_nurses: dto.required_charge_nurses ?? 0,
      required_cnas: dto.required_cnas ?? 0,
      required_sitters: dto.required_sitters ?? 0,
      required_treatment_nurses: dto.required_treatment_nurses ?? 0,
      required_nps: dto.required_nps ?? 0,
      required_mds: dto.required_mds ?? 0,
      multi_station_am: dto.multi_station_am ?? false,
      multi_station_pm: dto.multi_station_pm ?? false,
      multi_station_noc: dto.multi_station_noc ?? false,
      configuration_type: dto.configuration_type ?? null,
      default_beds_per_room: dto.default_beds_per_room ?? null,
      default_chairs_per_room: dto.default_chairs_per_room ?? null,
      custom_shift_times: dto.custom_shift_times ?? null,
      is_active: dto.is_active ?? true,
      sort_order: dto.sort_order ?? null,
    });
    const saved = await this.stationRepository.save(station);
    if (dto.rooms?.length) {
      const configType = dto.configuration_type ?? 'BEDS';
      for (let i = 0; i < dto.rooms.length; i++) {
        const item = dto.rooms[i];
        const bedsCount = configType === 'BEDS' ? (item.beds ?? dto.default_beds_per_room ?? 0) : 0;
        const chairsCount = configType === 'CHAIRS' ? (item.chairs ?? dto.default_chairs_per_room ?? 0) : 0;
        const room = await this.roomRepository.save(
          this.roomRepository.create({
            station_id: saved.id,
            name: item.name,
            configuration_type: configType,
            beds_per_room: bedsCount || null,
            chairs_per_room: chairsCount || null,
            is_active: true,
            sort_order: i,
          }),
        );
        for (let b = 0; b < bedsCount; b++) {
          await this.bedRepository.save(
            this.bedRepository.create({
              room_id: room.id,
              bed_number: String(b + 1),
            }),
          );
        }
        for (let c = 0; c < chairsCount; c++) {
          await this.chairRepository.save(
            this.chairRepository.create({
              room_id: room.id,
              chair_number: String(c + 1),
            }),
          );
        }
      }
    }
    return saved;
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
    if (dto.location !== undefined) station.location = dto.location;
    if (dto.code !== undefined) station.code = dto.code;
    if (dto.required_charge_nurses !== undefined) station.required_charge_nurses = dto.required_charge_nurses;
    if (dto.required_cnas !== undefined) station.required_cnas = dto.required_cnas;
    if (dto.required_sitters !== undefined) station.required_sitters = dto.required_sitters;
    if (dto.required_treatment_nurses !== undefined) station.required_treatment_nurses = dto.required_treatment_nurses;
    if (dto.required_nps !== undefined) station.required_nps = dto.required_nps;
    if (dto.required_mds !== undefined) station.required_mds = dto.required_mds;
    if (dto.multi_station_am !== undefined) station.multi_station_am = dto.multi_station_am;
    if (dto.multi_station_pm !== undefined) station.multi_station_pm = dto.multi_station_pm;
    if (dto.multi_station_noc !== undefined) station.multi_station_noc = dto.multi_station_noc;
    if (dto.configuration_type !== undefined) station.configuration_type = dto.configuration_type;
    if (dto.default_beds_per_room !== undefined) station.default_beds_per_room = dto.default_beds_per_room;
    if (dto.default_chairs_per_room !== undefined) station.default_chairs_per_room = dto.default_chairs_per_room;
    if (dto.custom_shift_times !== undefined) station.custom_shift_times = dto.custom_shift_times;
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
