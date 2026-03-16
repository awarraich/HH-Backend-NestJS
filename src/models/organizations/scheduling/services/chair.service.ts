import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { Room } from '../entities/room.entity';
import { Chair } from '../entities/chair.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateChairDto } from '../dto/create-chair.dto';
import { UpdateChairDto } from '../dto/update-chair.dto';
import { QueryChairDto } from '../dto/query-chair.dto';

@Injectable()
export class ChairService {
  constructor(
    @InjectRepository(Chair)
    private readonly chairRepository: Repository<Chair>,
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

  private async ensureRoomInOrg(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
  ): Promise<Room> {
    const dept = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!dept) throw new NotFoundException('Department not found');
    const station = await this.stationRepository.findOne({
      where: { id: stationId, department_id: departmentId },
    });
    if (!station) throw new NotFoundException('Station not found');
    const room = await this.roomRepository.findOne({
      where: { id: roomId, station_id: stationId },
    });
    if (!room) throw new NotFoundException('Room not found');
    return room;
  }

  async findAll(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    query: QueryChairDto,
    userId: string,
  ): Promise<{ data: Chair[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureRoomInOrg(organizationId, departmentId, stationId, roomId);
    const { page = 1, limit = 20, is_active } = query;
    const skip = (page - 1) * limit;

    const qb = this.chairRepository
      .createQueryBuilder('c')
      .where('c.room_id = :roomId', { roomId });

    if (is_active !== undefined) {
      qb.andWhere('c.is_active = :is_active', { is_active });
    }
    qb.orderBy('c.chair_number', 'ASC');

    const [data, total] = await qb.skip(skip).take(limit).getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    chairId: string,
    userId: string,
  ): Promise<Chair> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureRoomInOrg(organizationId, departmentId, stationId, roomId);
    const chair = await this.chairRepository.findOne({
      where: { id: chairId, room_id: roomId },
    });
    if (!chair) throw new NotFoundException('Chair not found');
    return chair;
  }

  async create(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    dto: CreateChairDto,
    userId: string,
  ): Promise<Chair> {
    await this.ensureAccess(organizationId, userId);
    await this.ensureRoomInOrg(organizationId, departmentId, stationId, roomId);
    const chair = this.chairRepository.create({
      room_id: roomId,
      chair_number: dto.chair_number,
      is_active: dto.is_active ?? true,
    });
    return this.chairRepository.save(chair);
  }

  async update(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    chairId: string,
    dto: UpdateChairDto,
    userId: string,
  ): Promise<Chair> {
    await this.ensureAccess(organizationId, userId);
    const chair = await this.findOne(
      organizationId,
      departmentId,
      stationId,
      roomId,
      chairId,
      userId,
    );
    if (dto.chair_number !== undefined) chair.chair_number = dto.chair_number;
    if (dto.is_active !== undefined) chair.is_active = dto.is_active;
    return this.chairRepository.save(chair);
  }

  async remove(
    organizationId: string,
    departmentId: string,
    stationId: string,
    roomId: string,
    chairId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const chair = await this.findOne(
      organizationId,
      departmentId,
      stationId,
      roomId,
      chairId,
      userId,
    );
    await this.chairRepository.remove(chair);
  }
}
