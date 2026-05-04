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

    const { page = 1, limit = 20, employee_id, status, scheduled_date, from_date, to_date } = query;
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

  /**
   * Self-service variant of findByEmployee: returns the calling user's
   * own assigned shifts in a date range, without requiring the
   * OWNER/HR/MANAGER role gate. Used by the Google Chat agent's
   * `listMyShifts` tool — the caller is querying their own data.
   *
   * Resolves the caller's Employee record via (user_id, organization_id);
   * returns [] if the user has no Employee row in that org. Caller is
   * trusted to be authenticated upstream (the agent gates on its own
   * identity resolver before reaching here).
   */
  async findByCallerSelf(
    organizationId: string,
    userId: string,
    range: { from: string; to: string },
  ): Promise<EmployeeShift[]> {
    const employee = await this.employeeRepository.findOne({
      where: { user_id: userId, organization_id: organizationId },
    });
    if (!employee) return [];

    return this.employeeShiftRepository
      .createQueryBuilder('es')
      .innerJoinAndSelect('es.shift', 'shift')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.station', 'station')
      .leftJoinAndSelect('es.room', 'room')
      .leftJoinAndSelect('es.bed', 'bed')
      .leftJoinAndSelect('es.chair', 'chair')
      .where('es.employee_id = :employeeId', { employeeId: employee.id })
      .andWhere('shift.organization_id = :organizationId', { organizationId })
      .andWhere('es.scheduled_date >= :from', { from: range.from })
      .andWhere('es.scheduled_date <= :to', { to: range.to })
      .orderBy('es.scheduled_date', 'ASC')
      .addOrderBy('shift.start_at', 'ASC')
      .getMany();
  }

  /**
   * Self-service variant: returns a Shift's details PLUS the caller's
   * own assignments to it. If the caller is not assigned to the shift
   * (or not employed in the shift's org), returns null — the agent
   * surfaces this as "you're not assigned to that shift".
   */
  async findShiftDetailsForCallerSelf(
    organizationId: string,
    userId: string,
    shiftId: string,
  ): Promise<{ shift: Shift; assignments: EmployeeShift[] } | null> {
    const employee = await this.employeeRepository.findOne({
      where: { user_id: userId, organization_id: organizationId },
    });
    if (!employee) return null;

    const shift = await this.shiftRepository.findOne({
      where: { id: shiftId, organization_id: organizationId },
      relations: ['shiftRoles', 'shiftRoles.providerRole'],
    });
    if (!shift) return null;

    const assignments = await this.employeeShiftRepository
      .createQueryBuilder('es')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.station', 'station')
      .leftJoinAndSelect('es.room', 'room')
      .leftJoinAndSelect('es.bed', 'bed')
      .leftJoinAndSelect('es.chair', 'chair')
      .where('es.employee_id = :employeeId', { employeeId: employee.id })
      .andWhere('es.shift_id = :shiftId', { shiftId })
      .orderBy('es.scheduled_date', 'ASC')
      .getMany();

    if (assignments.length === 0) return null;

    return { shift, assignments };
  }

  /**
   * Self-service: shifts the caller could potentially be assigned to.
   * Filtered to shifts whose role requirements match the caller's
   * provider_role (role-agnostic shifts always included). Date-range
   * filtering uses the same one-time-vs-recurring logic as ShiftService.findAll.
   *
   * Returns active shifts in the caller's org. Read-only — does NOT
   * self-assign. The agent renders a "talk to your manager" hint.
   */
  async findAvailableForCallerSelf(
    organizationId: string,
    userId: string,
    range: { from: string; to: string },
  ): Promise<Shift[]> {
    const employee = await this.employeeRepository.findOne({
      where: { user_id: userId, organization_id: organizationId },
    });
    if (!employee) return [];

    const isDateOnly = (v: string) => /^\d{4}-\d{2}-\d{2}$/.test(v);
    const fromBound = isDateOnly(range.from)
      ? `${range.from} 00:00:00`
      : range.from;
    const toBound = isDateOnly(range.to)
      ? `${range.to} 23:59:59`
      : range.to;

    const qb = this.shiftRepository
      .createQueryBuilder('s')
      .leftJoinAndSelect('s.shiftRoles', 'sr')
      .leftJoinAndSelect('sr.providerRole', 'pr')
      .where('s.organization_id = :organizationId', { organizationId })
      .andWhere("UPPER(s.status) = 'ACTIVE'")
      .andWhere(
        '((s.recurrence_type = :oneTime AND s.end_at > :fromBound AND s.start_at < :toBound) ' +
          'OR (s.recurrence_type != :oneTime ' +
          '    AND (s.recurrence_end_date IS NULL OR s.recurrence_end_date >= :fromDate) ' +
          '    AND (s.recurrence_start_date IS NULL OR s.recurrence_start_date <= :toDate)))',
        {
          oneTime: 'ONE_TIME',
          fromBound,
          toBound,
          fromDate: range.from,
          toDate: range.to,
        },
      );

    // Role match: include shifts with no shiftRoles entries (role-agnostic)
    // OR shifts with a shiftRole matching the caller's provider_role_id.
    if (employee.provider_role_id) {
      qb.andWhere(
        '(NOT EXISTS (SELECT 1 FROM shift_roles srx WHERE srx.shift_id = s.id) ' +
          'OR EXISTS (SELECT 1 FROM shift_roles sry WHERE sry.shift_id = s.id AND sry.provider_role_id = :providerRoleId))',
        { providerRoleId: employee.provider_role_id },
      );
    } else {
      // Caller has no provider_role assigned — only show role-agnostic shifts.
      qb.andWhere(
        'NOT EXISTS (SELECT 1 FROM shift_roles srx WHERE srx.shift_id = s.id)',
      );
    }

    qb.orderBy('s.start_at', 'ASC').take(50);
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
}
