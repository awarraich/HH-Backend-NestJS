import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Shift } from '../entities/shift.entity';
import { EmployeeShift } from '../entities/employee-shift.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { Room } from '../entities/room.entity';
import { Bed } from '../entities/bed.entity';
import { Chair } from '../entities/chair.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateEmployeeShiftDto } from '../dto/create-employee-shift.dto';
import { UpdateEmployeeShiftDto } from '../dto/update-employee-shift.dto';
import { QueryEmployeeShiftDto } from '../dto/query-employee-shift.dto';
import { QueryEmployeeShiftsByEmployeeDto } from '../dto/query-employee-shifts-by-employee.dto';

@Injectable()
export class EmployeeShiftService {
  constructor(
    @InjectRepository(EmployeeShift)
    private readonly employeeShiftRepository: Repository<EmployeeShift>,
    @InjectRepository(Shift)
    private readonly shiftRepository: Repository<Shift>,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
    @InjectRepository(Station)
    private readonly stationRepository: Repository<Station>,
    @InjectRepository(Room)
    private readonly roomRepository: Repository<Room>,
    @InjectRepository(Bed)
    private readonly bedRepository: Repository<Bed>,
    @InjectRepository(Chair)
    private readonly chairRepository: Repository<Chair>,
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

  private async validateLocationInOrg(
    organizationId: string,
    dto: {
      department_id?: string;
      station_id?: string;
      room_id?: string;
      bed_id?: string;
      chair_id?: string;
    },
  ): Promise<void> {
    const hasLocation =
      dto.department_id ||
      dto.station_id ||
      dto.room_id ||
      dto.bed_id ||
      dto.chair_id;
    if (!hasLocation) return;

    if (dto.department_id) {
      const dept = await this.departmentRepository.findOne({
        where: { id: dto.department_id, organization_id: organizationId },
      });
      if (!dept) throw new BadRequestException('Invalid department for this organization');
    }
    if (dto.station_id) {
      const station = await this.stationRepository.findOne({
        where: { id: dto.station_id },
        relations: ['department'],
      });
      if (!station || station.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid station for this organization');
      }
    }
    if (dto.room_id) {
      const room = await this.roomRepository.findOne({
        where: { id: dto.room_id },
        relations: ['station', 'station.department'],
      });
      if (!room || room.station.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid room for this organization');
      }
    }
    if (dto.bed_id) {
      const bed = await this.bedRepository.findOne({
        where: { id: dto.bed_id },
        relations: ['room', 'room.station', 'room.station.department'],
      });
      if (!bed || bed.room.station.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid bed for this organization');
      }
    }
    if (dto.chair_id) {
      const chair = await this.chairRepository.findOne({
        where: { id: dto.chair_id },
        relations: ['room', 'room.station', 'room.station.department'],
      });
      if (
        !chair ||
        chair.room.station.department.organization_id !== organizationId
      ) {
        throw new BadRequestException('Invalid chair for this organization');
      }
    }
  }

  async findByShift(
    organizationId: string,
    shiftId: string,
    query: QueryEmployeeShiftDto,
    userId: string,
  ): Promise<{ data: EmployeeShift[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    const shift = await this.shiftRepository.findOne({
      where: { id: shiftId, organization_id: organizationId },
    });
    if (!shift) throw new NotFoundException('Shift not found');

    const { page = 1, limit = 20, employee_id, status } = query;
    const skip = (page - 1) * limit;

    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .leftJoinAndSelect('es.employee', 'employee')
      .leftJoinAndSelect('employee.user', 'user')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.station', 'station')
      .leftJoinAndSelect('es.room', 'room')
      .leftJoinAndSelect('es.bed', 'bed')
      .leftJoinAndSelect('es.chair', 'chair')
      .where('es.shift_id = :shiftId', { shiftId });

    if (employee_id) qb.andWhere('es.employee_id = :employee_id', { employee_id });
    if (status) qb.andWhere('es.status = :status', { status });
    qb.orderBy('es.created_at', 'ASC').skip(skip).take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    employeeShiftId: string,
    userId: string,
  ): Promise<EmployeeShift> {
    await this.ensureAccess(organizationId, userId);
    const es = await this.employeeShiftRepository.findOne({
      where: { id: employeeShiftId },
      relations: [
        'shift',
        'employee',
        'employee.user',
        'department',
        'station',
        'room',
        'bed',
        'chair',
      ],
    });
    if (!es || !es.shift || es.shift.organization_id !== organizationId) {
      throw new NotFoundException('Employee shift not found');
    }
    return es;
  }

  async create(
    organizationId: string,
    shiftId: string,
    dto: CreateEmployeeShiftDto,
    userId: string,
  ): Promise<EmployeeShift> {
    await this.ensureAccess(organizationId, userId);
    const shift = await this.shiftRepository.findOne({
      where: { id: shiftId, organization_id: organizationId },
    });
    if (!shift) throw new NotFoundException('Shift not found');

    const employee = await this.employeeRepository.findOne({
      where: { id: dto.employee_id, organization_id: organizationId },
    });
    if (!employee) throw new BadRequestException('Employee not in this organization');

    const existing = await this.employeeShiftRepository.findOne({
      where: { shift_id: shiftId, employee_id: dto.employee_id },
    });
    if (existing) throw new ConflictException('Employee already assigned to this shift');

    await this.validateLocationInOrg(organizationId, dto);

    const employeeShift = this.employeeShiftRepository.create({
      shift_id: shiftId,
      employee_id: dto.employee_id,
      department_id: dto.department_id ?? null,
      station_id: dto.station_id ?? null,
      room_id: dto.room_id ?? null,
      bed_id: dto.bed_id ?? null,
      chair_id: dto.chair_id ?? null,
      status: dto.status ?? 'SCHEDULED',
      notes: dto.notes ?? null,
    });
    return this.employeeShiftRepository.save(employeeShift);
  }

  async update(
    organizationId: string,
    employeeShiftId: string,
    dto: UpdateEmployeeShiftDto,
    userId: string,
  ): Promise<EmployeeShift> {
    await this.ensureAccess(organizationId, userId);
    const es = await this.findOne(organizationId, employeeShiftId, userId);
    if (dto.department_id !== undefined) es.department_id = dto.department_id;
    if (dto.station_id !== undefined) es.station_id = dto.station_id;
    if (dto.room_id !== undefined) es.room_id = dto.room_id;
    if (dto.bed_id !== undefined) es.bed_id = dto.bed_id;
    if (dto.chair_id !== undefined) es.chair_id = dto.chair_id;
    if (dto.status !== undefined) es.status = dto.status;
    if (dto.notes !== undefined) es.notes = dto.notes;
    if (dto.actual_start_at !== undefined) es.actual_start_at = new Date(dto.actual_start_at);
    if (dto.actual_end_at !== undefined) es.actual_end_at = new Date(dto.actual_end_at);
    if (
      dto.department_id !== undefined ||
      dto.station_id !== undefined ||
      dto.room_id !== undefined ||
      dto.bed_id !== undefined ||
      dto.chair_id !== undefined
    ) {
      await this.validateLocationInOrg(organizationId, {
        department_id: es.department_id ?? undefined,
        station_id: es.station_id ?? undefined,
        room_id: es.room_id ?? undefined,
        bed_id: es.bed_id ?? undefined,
        chair_id: es.chair_id ?? undefined,
      });
    }
    return this.employeeShiftRepository.save(es);
  }

  async remove(organizationId: string, employeeShiftId: string, userId: string): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const es = await this.findOne(organizationId, employeeShiftId, userId);
    await this.employeeShiftRepository.remove(es);
  }

  /**
   * List all employee-shift assignments in an organization, optionally
   * filtered by shift_id or employee_id. Used by the MCP `list_roles` tool
   * when no shift- or employee-specific scope is provided.
   */
  async findAllInOrg(
    organizationId: string,
    filters: { shift_id?: string; employee_id?: string; status?: string; limit?: number },
    userId: string,
  ): Promise<EmployeeShift[]> {
    await this.ensureAccess(organizationId, userId);
    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .innerJoinAndSelect('es.shift', 'shift')
      .leftJoinAndSelect('es.employee', 'employee')
      .leftJoinAndSelect('employee.user', 'user')
      .where('shift.organization_id = :organizationId', { organizationId });

    if (filters.shift_id) qb.andWhere('es.shift_id = :shift_id', { shift_id: filters.shift_id });
    if (filters.employee_id) qb.andWhere('es.employee_id = :employee_id', { employee_id: filters.employee_id });
    if (filters.status) qb.andWhere('es.status = :status', { status: filters.status });

    qb.orderBy('shift.start_at', 'ASC').take(filters.limit ?? 50);
    return qb.getMany();
  }

  async findByEmployee(
    organizationId: string,
    employeeId: string,
    query: QueryEmployeeShiftsByEmployeeDto,
    userId: string,
  ): Promise<{ data: EmployeeShift[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
    });
    if (!employee) throw new NotFoundException('Employee not found');

    const { page = 1, limit = 20, from_date, to_date, status } = query;
    const skip = (page - 1) * limit;

    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .innerJoinAndSelect('es.shift', 'shift')
      .leftJoinAndSelect('es.employee', 'employee')
      .leftJoinAndSelect('employee.user', 'user')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.station', 'station')
      .where('es.employee_id = :employeeId', { employeeId })
      .andWhere('shift.organization_id = :organizationId', { organizationId });

    if (from_date) {
      qb.andWhere('shift.start_at >= :from_date', { from_date: new Date(from_date) });
    }
    if (to_date) {
      qb.andWhere('shift.end_at <= :to_date', { to_date: new Date(to_date) });
    }
    if (status) {
      qb.andWhere('es.status = :status', { status });
    }
    qb.orderBy('shift.start_at', 'ASC').skip(skip).take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }
}
