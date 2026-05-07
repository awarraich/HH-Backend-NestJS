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
import { StationShiftAssignment } from '../entities/station-shift-assignment.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateEmployeeShiftDto } from '../dto/create-employee-shift.dto';
import { UpdateEmployeeShiftDto } from '../dto/update-employee-shift.dto';
import { QueryEmployeeShiftDto } from '../dto/query-employee-shift.dto';
import { QueryEmployeeShiftsByEmployeeDto } from '../dto/query-employee-shifts-by-employee.dto';
import { GetBedMapDto } from '../dto/get-bed-map.dto';
import { BulkClearEmployeeShiftsDto } from '../dto/bulk-clear-employee-shifts.dto';

function formatDateOnly(d: string | Date): string {
  if (typeof d === 'string') return d.slice(0, 10);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

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
    @InjectRepository(StationShiftAssignment)
    private readonly stationShiftAssignmentRepository: Repository<StationShiftAssignment>,
    private readonly organizationRoleService: OrganizationRoleService,
  ) {}


  private async resolveStationForShift(
    shiftId: string,
    providedStationId?: string,
  ): Promise<Station | null> {
    const links = await this.stationShiftAssignmentRepository.find({
      where: { shift_id: shiftId },
      relations: ['station', 'station.department'],
    });

    if (providedStationId) {
      const match = links.find((l) => l.station_id === providedStationId);
      if (!match) {
        if (links.length === 0) {
          return this.stationRepository.findOne({
            where: { id: providedStationId },
            relations: ['department'],
          });
        }
        const valid = links
          .map((l) => `${l.station?.name ?? 'unnamed'} (${l.station_id})`)
          .join(', ');
        throw new BadRequestException(
          `station_id ${providedStationId} is not linked to this shift. Valid stations: ${valid}`,
        );
      }
      return match.station;
    }

    if (links.length === 1) return links[0].station;
    if (links.length === 0) return null;

    const valid = links
      .map((l) => `${l.station?.name ?? 'unnamed'} (${l.station_id})`)
      .join(', ');
    throw new BadRequestException(
      `This shift is offered at multiple stations; station_id is required. Valid stations: ${valid}`,
    );
  }


  async getStationLinksForShift(shiftId: string): Promise<string[]> {
    const links = await this.stationShiftAssignmentRepository.find({
      where: { shift_id: shiftId },
      select: ['station_id'],
    });
    return links.map((l) => l.station_id);
  }

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

  /**
   * Reject creating/moving an assignment onto a bed or chair that another
   * non-cancelled employee already occupies for the same shift+date.
   *
   * Mirrors the existing employee-side unique constraint (shift, employee,
   * date) but on the location side. Only consults rows that are still
   * "live" — DECLINED/REJECTED/CANCELLED don't claim a tile.
   *
   * Called from create() and update() when the caller sets bed_id or
   * chair_id. Existing callers that don't set those fields are unaffected.
   */
  private async assertFurnitureFree(
    shiftId: string,
    scheduledDate: string,
    furniture: { bed_id?: string | null; chair_id?: string | null },
    excludeEmployeeShiftId?: string,
  ): Promise<void> {
    const blockedStatuses = ['DECLINED', 'REJECTED', 'CANCELLED'];

    if (furniture.bed_id) {
      const qb = this.employeeShiftRepository
        .createQueryBuilder('es')
        .leftJoinAndSelect('es.employee', 'employee')
        .leftJoinAndSelect('employee.user', 'user')
        .where('es.shift_id = :shiftId', { shiftId })
        .andWhere('es.scheduled_date = :scheduledDate', { scheduledDate })
        .andWhere('es.bed_id = :bedId', { bedId: furniture.bed_id })
        .andWhere('es.status NOT IN (:...blocked)', { blocked: blockedStatuses });
      if (excludeEmployeeShiftId) {
        qb.andWhere('es.id != :excludeId', { excludeId: excludeEmployeeShiftId });
      }
      const clash = await qb.getOne();
      if (clash) {
        const who =
          [clash.employee?.user?.firstName, clash.employee?.user?.lastName]
            .filter(Boolean)
            .join(' ')
            .trim() || 'another employee';
        throw new ConflictException(
          `This bed is already assigned to ${who} on this shift+date.`,
        );
      }
    }

    if (furniture.chair_id) {
      const qb = this.employeeShiftRepository
        .createQueryBuilder('es')
        .leftJoinAndSelect('es.employee', 'employee')
        .leftJoinAndSelect('employee.user', 'user')
        .where('es.shift_id = :shiftId', { shiftId })
        .andWhere('es.scheduled_date = :scheduledDate', { scheduledDate })
        .andWhere('es.chair_id = :chairId', { chairId: furniture.chair_id })
        .andWhere('es.status NOT IN (:...blocked)', { blocked: blockedStatuses });
      if (excludeEmployeeShiftId) {
        qb.andWhere('es.id != :excludeId', { excludeId: excludeEmployeeShiftId });
      }
      const clash = await qb.getOne();
      if (clash) {
        const who =
          [clash.employee?.user?.firstName, clash.employee?.user?.lastName]
            .filter(Boolean)
            .join(' ')
            .trim() || 'another employee';
        throw new ConflictException(
          `This chair is already assigned to ${who} on this shift+date.`,
        );
      }
    }
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

    const {
      page = 1,
      limit = 20,
      employee_id,
      status,
      scheduled_date,
      from_date,
      to_date,
      station_id,
      room_id,
      bed_id,
      chair_id,
      role,
    } = query;
    const skip = (page - 1) * limit;

    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .leftJoinAndSelect('es.employee', 'employee')
      .leftJoinAndSelect('employee.user', 'user')
      .leftJoinAndSelect('employee.providerRole', 'providerRole')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.station', 'station')
      .leftJoinAndSelect('es.room', 'room')
      .leftJoinAndSelect('es.bed', 'bed')
      .leftJoinAndSelect('es.chair', 'chair')
      .where('es.shift_id = :shiftId', { shiftId });

    if (employee_id) qb.andWhere('es.employee_id = :employee_id', { employee_id });
    if (status) qb.andWhere('es.status = :status', { status });
    if (scheduled_date) qb.andWhere('es.scheduled_date = :scheduled_date', { scheduled_date });
    if (from_date) qb.andWhere('es.scheduled_date >= :from_date', { from_date });
    if (to_date) qb.andWhere('es.scheduled_date <= :to_date', { to_date });
    if (station_id) qb.andWhere('es.station_id = :station_id', { station_id });
    if (room_id) qb.andWhere('es.room_id = :room_id', { room_id });
    if (bed_id) qb.andWhere('es.bed_id = :bed_id', { bed_id });
    if (chair_id) qb.andWhere('es.chair_id = :chair_id', { chair_id });
    if (role) qb.andWhere('es.role = :role', { role });
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

    // Determine scheduled_date: use provided value, or derive from shift
    const isRecurring =
      shift.recurrence_type &&
      shift.recurrence_type.toUpperCase() !== 'ONE_TIME';

    let scheduledDate = dto.scheduled_date;
    if (!scheduledDate) {
      if (isRecurring) {
        throw new BadRequestException(
          'scheduled_date is required when assigning to a recurring shift',
        );
      }
      // ONE_TIME: derive from the shift's start_at
      scheduledDate = shift.start_at.toISOString().slice(0, 10);
    }

    const existing = await this.employeeShiftRepository.findOne({
      where: {
        shift_id: shiftId,
        employee_id: dto.employee_id,
        scheduled_date: scheduledDate,
      },
    });
    if (existing) {
      throw new ConflictException(
        'Employee already assigned to this shift on this date',
      );
    }

    const resolvedStation = await this.resolveStationForShift(
      shiftId,
      dto.station_id,
    );
    const stationId = resolvedStation?.id ?? dto.station_id ?? null;
    const departmentId =
      dto.department_id ?? resolvedStation?.department_id ?? null;

    await this.validateLocationInOrg(organizationId, {
      department_id: departmentId ?? undefined,
      station_id: stationId ?? undefined,
      room_id: dto.room_id,
      bed_id: dto.bed_id,
      chair_id: dto.chair_id,
    });

    await this.assertFurnitureFree(shiftId, scheduledDate, {
      bed_id: dto.bed_id,
      chair_id: dto.chair_id,
    });

    const employeeShift = this.employeeShiftRepository.create({
      shift_id: shiftId,
      employee_id: dto.employee_id,
      scheduled_date: scheduledDate,
      department_id: departmentId,
      station_id: stationId,
      room_id: dto.room_id ?? null,
      bed_id: dto.bed_id ?? null,
      chair_id: dto.chair_id ?? null,
      status: dto.status ?? 'SCHEDULED',
      role: dto.role ?? null,
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
    if (dto.scheduled_date !== undefined) es.scheduled_date = dto.scheduled_date;
    if (dto.department_id !== undefined) es.department_id = dto.department_id;
    if (dto.station_id !== undefined) es.station_id = dto.station_id;
    if (dto.room_id !== undefined) es.room_id = dto.room_id;
    if (dto.bed_id !== undefined) es.bed_id = dto.bed_id;
    if (dto.chair_id !== undefined) es.chair_id = dto.chair_id;
    if (dto.status !== undefined) es.status = dto.status;
    if (dto.role !== undefined) es.role = dto.role;
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

    // Only re-check furniture occupancy when the caller actually changes
    // bed_id or chair_id — otherwise we'd false-positive against the row
    // we're updating. Exclude the current row from the lookup either way.
    if (dto.bed_id !== undefined || dto.chair_id !== undefined) {
      await this.assertFurnitureFree(
        es.shift_id,
        es.scheduled_date,
        { bed_id: es.bed_id ?? null, chair_id: es.chair_id ?? null },
        es.id,
      );
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
      .leftJoinAndSelect('employee.providerRole', 'providerRole')
      .where('shift.organization_id = :organizationId', { organizationId });

    if (filters.shift_id) qb.andWhere('es.shift_id = :shift_id', { shift_id: filters.shift_id });
    if (filters.employee_id) qb.andWhere('es.employee_id = :employee_id', { employee_id: filters.employee_id });
    if (filters.status) qb.andWhere('es.status = :status', { status: filters.status });

    qb.orderBy('shift.start_at', 'ASC').take(filters.limit ?? 50);
    return qb.getMany();
  }

  async findAssignmentsForEmployees(
    organizationId: string,
    employeeIds: string[],
  ): Promise<
    Array<{
      employee_id: string;
      shift_id: string;
      shift_name: string | null;
      scheduled_date: string;
      status: string;
    }>
  > {
    if (employeeIds.length === 0) return [];

    const rows = await this.employeeShiftRepository
      .createQueryBuilder('es')
      .innerJoin('es.shift', 'shift')
      .where('shift.organization_id = :organizationId', { organizationId })
      .andWhere('es.employee_id IN (:...employeeIds)', { employeeIds })
      .select([
        'es.employee_id AS employee_id',
        'es.shift_id AS shift_id',
        'shift.name AS shift_name',
        'es.scheduled_date AS scheduled_date',
        'es.status AS status',
      ])
      .orderBy('es.scheduled_date', 'ASC')
      .getRawMany<{
        employee_id: string;
        shift_id: string;
        shift_name: string | null;
        scheduled_date: string | Date;
        status: string;
      }>();

    return rows.map((r) => ({
      employee_id: r.employee_id,
      shift_id: r.shift_id,
      shift_name: r.shift_name,
      scheduled_date: formatDateOnly(r.scheduled_date),
      status: r.status,
    }));
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
      .leftJoinAndSelect('employee.providerRole', 'providerRole')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.station', 'station')
      .where('es.employee_id = :employeeId', { employeeId })
      .andWhere('shift.organization_id = :organizationId', { organizationId });

    if (from_date) {
      qb.andWhere('es.scheduled_date >= :from_date', { from_date });
    }
    if (to_date) {
      qb.andWhere('es.scheduled_date <= :to_date', { to_date });
    }
    if (status) {
      qb.andWhere('es.status = :status', { status });
    }
    qb.orderBy('es.scheduled_date', 'ASC')
      .addOrderBy('shift.start_at', 'ASC')
      .skip(skip)
      .take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  // ─── Bed Map snapshot ────────────────────────────────────────────────

  /**
   * Single comprehensive endpoint for the Employee Scheduling > Bed Map
   * view. Bundles the rooms (with their real bed + chair records eager-
   * loaded) and the live employee_shift rows for a (station, shift, date)
   * tuple plus pre-computed stats.
   *
   * Replaces the legacy 1 + 2N round-trip pattern (1 list-rooms call + 2
   * list-furniture calls per room) with a single fetch. shift_id +
   * scheduled_date are optional — when omitted, only the room layout is
   * returned and assignments + stats are zeroed.
   */
  async getBedMap(
    organizationId: string,
    query: GetBedMapDto,
    userId: string,
  ): Promise<{
    station: { id: string; name: string };
    shift: {
      id: string;
      name: string | null;
      shift_type: string | null;
      start_at: Date;
      end_at: Date;
    } | null;
    rooms: Array<{
      id: string;
      name: string;
      location_or_wing: string | null;
      floor: string | null;
      configuration_type: string | null;
      beds_per_room: number | null;
      chairs_per_room: number | null;
      is_active: boolean;
      sort_order: number | null;
      beds: Array<{ id: string; bed_number: string; is_active: boolean }>;
      chairs: Array<{ id: string; chair_number: string; is_active: boolean }>;
    }>;
    assignments: Array<{
      id: string;
      employee_id: string;
      scheduled_date: string;
      status: string;
      role: string | null;
      department_id: string | null;
      station_id: string | null;
      room_id: string | null;
      bed_id: string | null;
      chair_id: string | null;
      notes: string | null;
      employee: {
        id: string;
        first_name: string;
        last_name: string;
        provider_role_code: string | null;
      } | null;
    }>;
    stats: {
      total_beds: number;
      total_chairs: number;
      assigned_beds: number;
      assigned_chairs: number;
      vacant: number;
      coverage_percent: number;
      by_role: Array<{ code: string; count: number }>;
    };
  }> {
    await this.ensureAccess(organizationId, userId);

    // Validate station belongs to this org via the department chain.
    const station = await this.stationRepository.findOne({
      where: { id: query.station_id },
      relations: ['department'],
    });
    if (!station || station.department.organization_id !== organizationId) {
      throw new BadRequestException('Invalid station for this organization');
    }

    // Optional shift validation — only when the caller is asking for
    // assignments on top of the layout.
    let shiftEntity: Shift | null = null;
    if (query.shift_id) {
      shiftEntity = await this.shiftRepository.findOne({
        where: { id: query.shift_id, organization_id: organizationId },
      });
      if (!shiftEntity) throw new NotFoundException('Shift not found');
      if (!query.scheduled_date) {
        throw new BadRequestException(
          'scheduled_date is required when shift_id is provided',
        );
      }
    }

    // Rooms with eager beds + chairs in one query. We deliberately keep
    // inactive rooms out — managers should fix them in setup, not assign
    // employees to them.
    const rawRooms = await this.roomRepository.find({
      where: { station_id: query.station_id, is_active: true },
      relations: ['beds', 'chairs'],
      order: { sort_order: 'ASC', name: 'ASC' },
    });

    // Natural-sort beds + chairs within each room so "Bed 2" sorts before
    // "Bed 10" — matches the existing front-end expectation.
    const naturalCompare = (a: string, b: string) =>
      a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });

    const rooms = rawRooms.map((r) => {
      const activeBeds = (r.beds ?? [])
        .filter((b) => b.is_active !== false)
        .sort((a, b) => naturalCompare(a.bed_number, b.bed_number));
      const activeChairs = (r.chairs ?? [])
        .filter((c) => c.is_active !== false)
        .sort((a, b) => naturalCompare(a.chair_number, b.chair_number));
      return {
        id: r.id,
        name: r.name,
        location_or_wing: r.location_or_wing,
        floor: r.floor,
        configuration_type: r.configuration_type,
        beds_per_room: r.beds_per_room,
        chairs_per_room: r.chairs_per_room,
        is_active: r.is_active,
        sort_order: r.sort_order,
        beds: activeBeds.map((b) => ({
          id: b.id,
          bed_number: b.bed_number,
          is_active: b.is_active,
        })),
        chairs: activeChairs.map((c) => ({
          id: c.id,
          chair_number: c.chair_number,
          is_active: c.is_active,
        })),
      };
    });

    // Assignments: only fetch when both shift_id + scheduled_date are
    // supplied. We return all rows (incl. DECLINED) so the client can
    // decide whether to reactivate or display them; stats only count
    // live (non-cancelled) rows.
    let assignments: EmployeeShift[] = [];
    if (shiftEntity && query.scheduled_date) {
      assignments = await this.employeeShiftRepository
        .createQueryBuilder('es')
        .leftJoinAndSelect('es.employee', 'employee')
        .leftJoinAndSelect('employee.user', 'user')
        .leftJoinAndSelect('employee.providerRole', 'providerRole')
        .where('es.shift_id = :shiftId', { shiftId: shiftEntity.id })
        .andWhere('es.scheduled_date = :scheduledDate', {
          scheduledDate: query.scheduled_date,
        })
        .andWhere('es.station_id = :stationId', { stationId: station.id })
        .orderBy('es.created_at', 'ASC')
        .getMany();
    }

    // Pre-computed stats — keep in lockstep with the front-end. Hidden
    // statuses (DECLINED/REJECTED/CANCELLED) don't claim a tile and are
    // excluded from the role + occupancy counters.
    const blockedStatuses = new Set(['DECLINED', 'REJECTED', 'CANCELLED']);
    const liveAssignments = assignments.filter(
      (a) => !blockedStatuses.has((a.status ?? '').toUpperCase()),
    );

    const totalBeds = rooms.reduce((s, r) => s + r.beds.length, 0);
    const totalChairs = rooms.reduce((s, r) => s + r.chairs.length, 0);
    const assignedBeds = liveAssignments.filter((a) => a.bed_id).length;
    const assignedChairs = liveAssignments.filter((a) => a.chair_id).length;
    const total = totalBeds + totalChairs;
    const assigned = assignedBeds + assignedChairs;

    const roleCounts = new Map<string, number>();
    for (const a of liveAssignments) {
      const code = (a.role ?? '').trim();
      if (!code) continue;
      roleCounts.set(code, (roleCounts.get(code) ?? 0) + 1);
    }

    return {
      station: { id: station.id, name: station.name },
      shift: shiftEntity
        ? {
            id: shiftEntity.id,
            name: shiftEntity.name ?? null,
            shift_type: shiftEntity.shift_type ?? null,
            start_at: shiftEntity.start_at,
            end_at: shiftEntity.end_at,
          }
        : null,
      rooms,
      assignments: assignments.map((a) => ({
        id: a.id,
        employee_id: a.employee_id,
        scheduled_date:
          typeof a.scheduled_date === 'string'
            ? a.scheduled_date
            : formatDateOnly(a.scheduled_date),
        status: a.status,
        role: a.role,
        department_id: a.department_id,
        station_id: a.station_id,
        room_id: a.room_id,
        bed_id: a.bed_id,
        chair_id: a.chair_id,
        notes: a.notes,
        employee: a.employee
          ? {
              id: a.employee.id,
              first_name: a.employee.user?.firstName ?? '',
              last_name: a.employee.user?.lastName ?? '',
              provider_role_code: a.employee.providerRole?.code ?? null,
            }
          : null,
      })),
      stats: {
        total_beds: totalBeds,
        total_chairs: totalChairs,
        assigned_beds: assignedBeds,
        assigned_chairs: assignedChairs,
        vacant: Math.max(total - assigned, 0),
        coverage_percent: total > 0 ? Math.round((assigned / total) * 100) : 0,
        by_role: [...roleCounts.entries()]
          .map(([code, count]) => ({ code, count }))
          .sort((a, b) => b.count - a.count),
      },
    };
  }

  /**
   * Atomic bulk-clear. Caller must scope to either a room or a station
   * (in addition to the required shift_id + scheduled_date) so we never
   * accidentally wipe an entire shift's roster. Returns the number of
   * deleted rows for honest UI feedback.
   */
  async bulkClear(
    organizationId: string,
    dto: BulkClearEmployeeShiftsDto,
    userId: string,
  ): Promise<{ deleted: number }> {
    await this.ensureAccess(organizationId, userId);

    if (!dto.room_id && !dto.station_id) {
      throw new BadRequestException(
        'bulk-clear requires either room_id or station_id to scope the deletion',
      );
    }

    // Validate shift ownership.
    const shift = await this.shiftRepository.findOne({
      where: { id: dto.shift_id, organization_id: organizationId },
    });
    if (!shift) throw new NotFoundException('Shift not found');

    // Validate the location scope belongs to this org so cross-tenant
    // ids can't slip through.
    if (dto.room_id) {
      const room = await this.roomRepository.findOne({
        where: { id: dto.room_id },
        relations: ['station', 'station.department'],
      });
      if (!room || room.station.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid room for this organization');
      }
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

    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .where('es.shift_id = :shiftId', { shiftId: dto.shift_id })
      .andWhere('es.scheduled_date = :scheduledDate', {
        scheduledDate: dto.scheduled_date,
      });
    if (dto.room_id) qb.andWhere('es.room_id = :roomId', { roomId: dto.room_id });
    if (dto.station_id) qb.andWhere('es.station_id = :stationId', { stationId: dto.station_id });

    const targets = await qb.getMany();
    if (targets.length === 0) return { deleted: 0 };

    await this.employeeShiftRepository.remove(targets);
    return { deleted: targets.length };
  }
}
