import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { Room } from '../entities/room.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateRoomDto } from '../dto/create-room.dto';
import { UpdateRoomDto } from '../dto/update-room.dto';
import { QueryRoomDto } from '../dto/query-room.dto';

@Injectable()
export class RoomService {
  constructor(
    @InjectRepository(Room)
    private readonly roomRepository: Repository<Room>,
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

  private async ensureStationInOrg(
    organizationId: string,
    departmentId: string,
    stationId: string,
  ): Promise<Station> {
    const dept = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!dept) throw new NotFoundException('Department not found');
    const station = await this.stationRepository.findOne({
      where: { id: stationId, department_id: departmentId },
    });
    if (!station) throw new NotFoundException('Station not found');
    return station;
  }

  async findAll(
    organizationId: string,
    departmentId: string,
    stationId: string,
    query: QueryRoomDto,
    userId: string,
  ): Promise<{ data: Room[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureStationInOrg(organizationId, departmentId, stationId);
    const { page = 1, limit = 20, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.roomRepository
      .createQueryBuilder('r')
      .where('r.station_id = :stationId', { stationId });

    if (is_active !== undefined) {
      qb.andWhere('r.is_active = :is_active', { is_active });
    }
    qb.orderBy('r.sort_order', 'ASC', 'NULLS LAST').addOrderBy('r.name', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    userId: string,
  ): Promise<Room> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureStationInOrg(organizationId, departmentId, stationId);
    const room = await this.roomRepository.findOne({
      where: { id: roomId, station_id: stationId },
    });
    if (!room) throw new NotFoundException('Room not found');
    return room;
  }

  async create(
    organizationId: string,
    departmentId: string,
    stationId: string,
    dto: CreateRoomDto,
    userId: string,
  ): Promise<Room> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureStationInOrg(organizationId, departmentId, stationId);
    const room = this.roomRepository.create({
      station_id: stationId,
      name: dto.name,
      is_active: dto.is_active ?? true,
      sort_order: dto.sort_order ?? null,
    });
    return this.roomRepository.save(room);
  }

  async update(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    dto: UpdateRoomDto,
    userId: string,
  ): Promise<Room> {
    await this.ensureAccess(organizationId, userId);
    const room = await this.findOne(organizationId, departmentId, stationId, roomId, userId);
    if (dto.name !== undefined) room.name = dto.name;
    if (dto.is_active !== undefined) room.is_active = dto.is_active;
    if (dto.sort_order !== undefined) room.sort_order = dto.sort_order;
    return this.roomRepository.save(room);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const room = await this.findOne(organizationId, departmentId, stationId, roomId, userId);
    await this.roomRepository.remove(room);
  }
}
