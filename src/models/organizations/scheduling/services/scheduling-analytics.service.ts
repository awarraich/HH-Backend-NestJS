import {
  Injectable,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EmployeeShift } from '../entities/employee-shift.entity';
import { Shift } from '../entities/shift.entity';
import { Station } from '../entities/station.entity';
import { Department } from '../entities/department.entity';
import { Bed } from '../entities/bed.entity';
import { Chair } from '../entities/chair.entity';
import { Room } from '../entities/room.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import {
  QueryAnalyticsDto,
  QueryHoursTrendDto,
  QueryUtilizationDto,
  QueryDayDetailDto,
  QueryResourceBrowseDto,
  QueryResourceAssignmentsDto,
  QueryDepartmentOverviewDto,
  type AnalyticsResourceType,
} from '../dto/query-analytics.dto';

const ACTIVE_STATUSES = ['SCHEDULED', 'CONFIRMED', 'ACCEPTED', 'COMPLETED', 'IN_PROGRESS'];
const DEFAULT_LOOKBACK_MONTHS = 6;

interface NormalizedRange {
  from: string;
  to: string;
}

interface EmployeeDisplayInfo {
  id: string;
  name: string;
  role_name: string | null;
  role_code: string | null;
  position_title: string | null;
}

@Injectable()
export class SchedulingAnalyticsService {
  constructor(
    @InjectRepository(EmployeeShift)
    private readonly employeeShiftRepository: Repository<EmployeeShift>,
    @InjectRepository(Shift)
    private readonly shiftRepository: Repository<Shift>,
    @InjectRepository(Station)
    private readonly stationRepository: Repository<Station>,
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
    @InjectRepository(Bed)
    private readonly bedRepository: Repository<Bed>,
    @InjectRepository(Chair)
    private readonly chairRepository: Repository<Chair>,
    @InjectRepository(Room)
    private readonly roomRepository: Repository<Room>,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    private readonly organizationRoleService: OrganizationRoleService,
  ) {}

  // ────────────────────── access + range guards ──────────────────────

  private async ensureAccess(organizationId: string, userId: string): Promise<void> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(
      userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (!canAccess) throw new ForbiddenException('No access to this organization.');
  }

  /**
   * The "previous months only" rule: the analytics view excludes the current
   * (in-progress) month entirely so trends and KPIs are read against finalized
   * data. We hard-clamp `to` to the last day of the previous calendar month
   * and reject any range whose `from` is in the current month or future.
   */
  private normalizeRange(input: QueryAnalyticsDto): NormalizedRange {
    const now = new Date();
    const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const previousMonthEnd = new Date(currentMonthStart);
    previousMonthEnd.setDate(previousMonthEnd.getDate() - 1);

    const defaultFrom = new Date(
      previousMonthEnd.getFullYear(),
      previousMonthEnd.getMonth() - (DEFAULT_LOOKBACK_MONTHS - 1),
      1,
    );

    const requestedFrom = input.from ? this.parseIsoDate(input.from) : defaultFrom;
    const requestedTo = input.to ? this.parseIsoDate(input.to) : previousMonthEnd;

    if (requestedFrom >= currentMonthStart) {
      throw new BadRequestException(
        'Analytics excludes the current month — choose a range ending in the previous month or earlier.',
      );
    }
    if (requestedTo < requestedFrom) {
      throw new BadRequestException('to must be on or after from.');
    }

    const effectiveTo = requestedTo > previousMonthEnd ? previousMonthEnd : requestedTo;

    return {
      from: this.toIsoDate(requestedFrom),
      to: this.toIsoDate(effectiveTo),
    };
  }

  private parseIsoDate(s: string): Date {
    const [y, m, d] = s.split('-').map(Number);
    if (!y || !m || !d) throw new BadRequestException(`Invalid date: ${s}`);
    return new Date(y, m - 1, d);
  }

  private toIsoDate(d: Date): string {
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  }

  // ──────────────────────── shared query base ────────────────────────

  /**
   * Builds the canonical employee_shifts query for the org, scoped to the
   * normalized analytics window and applying optional dimension filters.
   * All endpoints branch from this so they share the same row universe.
   */
  private buildBaseQuery(
    organizationId: string,
    range: NormalizedRange,
    filters: QueryAnalyticsDto,
  ) {
    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .innerJoin('es.shift', 's')
      .where('s.organization_id = :organizationId', { organizationId })
      .andWhere('es.scheduled_date BETWEEN :from AND :to', {
        from: range.from,
        to: range.to,
      });

    if (filters.department_id) {
      qb.andWhere('es.department_id = :departmentId', { departmentId: filters.department_id });
    }
    if (filters.station_id) {
      qb.andWhere('es.station_id = :stationId', { stationId: filters.station_id });
    }
    if (filters.role) {
      qb.andWhere('UPPER(es.role) = UPPER(:role)', { role: filters.role });
    }
    if (filters.shift_type) {
      qb.andWhere('UPPER(s.shift_type) = UPPER(:shiftType)', { shiftType: filters.shift_type });
    }
    return qb;
  }

  // ────────────────────────── public API ─────────────────────────────

  async getKpis(organizationId: string, query: QueryAnalyticsDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const baseQb = this.buildBaseQuery(organizationId, range, query);

    const totals: { total: string; filled: string; open: string; understaffed_stations: string } | undefined =
      await baseQb
        .clone()
        .select([
          'COUNT(*)::text AS total',
          `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
          `SUM(CASE WHEN UPPER(es.status) IN ('DECLINED','REJECTED','CANCELLED') OR es.employee_id IS NULL THEN 1 ELSE 0 END)::text AS open`,
        ])
        .getRawOne();

    const total = Number(totals?.total ?? 0);
    const filled = Number(totals?.filled ?? 0);
    const open = Number(totals?.open ?? 0);

    const hoursRow: { total_hours: string | null } | undefined = await baseQb
      .clone()
      .select([
        `COALESCE(SUM(EXTRACT(EPOCH FROM (s.end_at - s.start_at)) / 3600.0), 0)::text AS total_hours`,
      ])
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .getRawOne();
    const totalHours = Number(hoursRow?.total_hours ?? 0);

    const stationCoverage = await this.getCoverageByStation(organizationId, query, userId, range);
    const understaffed = stationCoverage.filter((s) => s.required > 0 && s.assigned < s.required).length;

    const utilization = await this.getUtilizationSummary(organizationId, range, query);

    return {
      range,
      total_shifts: total,
      filled_shifts: filled,
      open_shifts: open,
      coverage_percent: total > 0 ? Math.round((filled / total) * 1000) / 10 : 0,
      total_hours_scheduled: Math.round(totalHours * 10) / 10,
      avg_utilization_percent: utilization.avgPercent,
      understaffed_stations: understaffed,
    };
  }

  async getCalendar(organizationId: string, query: QueryAnalyticsDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const rows: Array<{
      day: string;
      total: string;
      filled: string;
      open: string;
      completed: string;
    }> = await this.buildBaseQuery(organizationId, range, query)
      .select([
        'es.scheduled_date AS day',
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('SCHEDULED','CONFIRMED','ACCEPTED','IN_PROGRESS') THEN 1 ELSE 0 END)::text AS filled`,
        `SUM(CASE WHEN UPPER(es.status) IN ('DECLINED','REJECTED','CANCELLED') THEN 1 ELSE 0 END)::text AS open`,
        `SUM(CASE WHEN UPPER(es.status) = 'COMPLETED' THEN 1 ELSE 0 END)::text AS completed`,
      ])
      .groupBy('es.scheduled_date')
      .orderBy('es.scheduled_date', 'ASC')
      .getRawMany();

    return {
      range,
      days: rows.map((r) => ({
        date: this.formatDay(r.day),
        total: Number(r.total),
        filled: Number(r.filled),
        open: Number(r.open),
        completed: Number(r.completed),
      })),
    };
  }

  async getShiftsByDay(organizationId: string, query: QueryAnalyticsDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const rows: Array<{ day: string; status: string; count: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        'es.scheduled_date AS day',
        'UPPER(COALESCE(es.status, \'UNKNOWN\')) AS status',
        'COUNT(*)::text AS count',
      ])
      .groupBy('es.scheduled_date, UPPER(COALESCE(es.status, \'UNKNOWN\'))')
      .orderBy('es.scheduled_date', 'ASC')
      .getRawMany();

    const byDay: Record<string, Record<string, number>> = {};
    for (const r of rows) {
      const date = this.formatDay(r.day);
      if (!byDay[date]) byDay[date] = {};
      byDay[date][r.status] = Number(r.count);
    }

    return {
      range,
      points: Object.entries(byDay).map(([date, statuses]) => ({
        date,
        ...statuses,
        total: Object.values(statuses).reduce((a, b) => a + b, 0),
      })),
    };
  }

  async getAssignmentsByRole(organizationId: string, query: QueryAnalyticsDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const rows: Array<{ role: string | null; count: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        'COALESCE(es.role, \'UNASSIGNED\') AS role',
        'COUNT(*)::text AS count',
      ])
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .groupBy('COALESCE(es.role, \'UNASSIGNED\')')
      .orderBy('count', 'DESC')
      .getRawMany();

    const total = rows.reduce((acc, r) => acc + Number(r.count), 0);
    return {
      range,
      total,
      slices: rows.map((r) => ({
        role: r.role ?? 'UNASSIGNED',
        count: Number(r.count),
        percent: total > 0 ? Math.round((Number(r.count) / total) * 1000) / 10 : 0,
      })),
    };
  }

  async getCoverageByStation(
    organizationId: string,
    query: QueryAnalyticsDto,
    userId: string,
    preNormalized?: NormalizedRange,
  ) {
    if (!preNormalized) await this.ensureAccess(organizationId, userId);
    const range = preNormalized ?? this.normalizeRange(query);

    const stationsQb = this.stationRepository
      .createQueryBuilder('st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('st.is_active = true');

    if (query.department_id) {
      stationsQb.andWhere('st.department_id = :departmentId', { departmentId: query.department_id });
    }
    if (query.station_id) {
      stationsQb.andWhere('st.id = :stationId', { stationId: query.station_id });
    }

    const stations = await stationsQb.getMany();

    const assignedRows: Array<{ station_id: string; assigned: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select(['es.station_id AS station_id', 'COUNT(*)::text AS assigned'])
      .andWhere('es.station_id IS NOT NULL')
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .groupBy('es.station_id')
      .getRawMany();

    const assignedById = new Map<string, number>();
    for (const r of assignedRows) assignedById.set(r.station_id, Number(r.assigned));

    return stations.map((st) => {
      const required =
        (st.required_charge_nurses ?? 0) +
        (st.required_cnas ?? 0) +
        (st.required_sitters ?? 0) +
        (st.required_treatment_nurses ?? 0) +
        (st.required_nps ?? 0) +
        (st.required_mds ?? 0);
      const assigned = assignedById.get(st.id) ?? 0;
      return {
        station_id: st.id,
        station_name: st.name,
        required,
        assigned,
        coverage_percent: required > 0 ? Math.round((assigned / required) * 1000) / 10 : null,
      };
    });
  }

  async getUtilization(organizationId: string, query: QueryUtilizationDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);
    const resource = query.resource ?? 'bed';

    const totalRow: { total: string } | undefined =
      resource === 'bed'
        ? await this.bedRepository
            .createQueryBuilder('b')
            .innerJoin('b.room', 'r')
            .innerJoin('r.station', 'st')
            .innerJoin('st.department', 'dept')
            .where('dept.organization_id = :organizationId', { organizationId })
            .andWhere('b.is_active = true')
            .select('COUNT(*)::text', 'total')
            .getRawOne()
        : await this.chairRepository
            .createQueryBuilder('c')
            .innerJoin('c.room', 'r')
            .innerJoin('r.station', 'st')
            .innerJoin('st.department', 'dept')
            .where('dept.organization_id = :organizationId', { organizationId })
            .andWhere('c.is_active = true')
            .select('COUNT(*)::text', 'total')
            .getRawOne();

    const totalResources = Number(totalRow?.total ?? 0);

    const column = resource === 'bed' ? 'es.bed_id' : 'es.chair_id';
    const rows: Array<{ station_id: string; day: string; assigned: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        'es.station_id AS station_id',
        'es.scheduled_date AS day',
        `COUNT(DISTINCT ${column}) ::text AS assigned`,
      ])
      .andWhere(`${column} IS NOT NULL`)
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .groupBy('es.station_id, es.scheduled_date')
      .getRawMany();

    const byStation: Record<string, { date: string; assigned: number }[]> = {};
    for (const r of rows) {
      if (!r.station_id) continue;
      const date = this.formatDay(r.day);
      if (!byStation[r.station_id]) byStation[r.station_id] = [];
      byStation[r.station_id].push({ date, assigned: Number(r.assigned) });
    }

    const stations = await this.stationRepository
      .createQueryBuilder('st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('st.is_active = true')
      .getMany();

    return {
      range,
      resource,
      total_resources: totalResources,
      stations: stations.map((st) => ({
        station_id: st.id,
        station_name: st.name,
        days: byStation[st.id] ?? [],
      })),
    };
  }

  private async getUtilizationSummary(
    organizationId: string,
    range: NormalizedRange,
    filters: QueryAnalyticsDto,
  ): Promise<{ avgPercent: number }> {
    const bedRow: { total: string } | undefined = await this.bedRepository
      .createQueryBuilder('b')
      .innerJoin('b.room', 'r')
      .innerJoin('r.station', 'st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('b.is_active = true')
      .select('COUNT(*)::text', 'total')
      .getRawOne();

    const chairRow: { total: string } | undefined = await this.chairRepository
      .createQueryBuilder('c')
      .innerJoin('c.room', 'r')
      .innerJoin('r.station', 'st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('c.is_active = true')
      .select('COUNT(*)::text', 'total')
      .getRawOne();

    const totalCapacity = Number(bedRow?.total ?? 0) + Number(chairRow?.total ?? 0);
    if (totalCapacity === 0) return { avgPercent: 0 };

    const usageRow: { used: string } | undefined = await this
      .buildBaseQuery(organizationId, range, filters)
      .select(
        'COUNT(DISTINCT COALESCE(es.bed_id, es.chair_id))::text',
        'used',
      )
      .andWhere('(es.bed_id IS NOT NULL OR es.chair_id IS NOT NULL)')
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .getRawOne();

    const used = Number(usageRow?.used ?? 0);
    return { avgPercent: Math.min(100, Math.round((used / totalCapacity) * 1000) / 10) };
  }

  async getHoursTrend(organizationId: string, query: QueryHoursTrendDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);
    const bucket = query.bucket ?? 'week';
    const truncUnit = bucket === 'day' ? 'day' : bucket === 'week' ? 'week' : 'month';

    const rows: Array<{ bucket_start: string; hours: string; shifts: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        `DATE_TRUNC('${truncUnit}', es.scheduled_date::timestamp) AS bucket_start`,
        `COALESCE(SUM(EXTRACT(EPOCH FROM (s.end_at - s.start_at)) / 3600.0), 0)::text AS hours`,
        `COUNT(*)::text AS shifts`,
      ])
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .groupBy('bucket_start')
      .orderBy('bucket_start', 'ASC')
      .getRawMany();

    return {
      range,
      bucket,
      points: rows.map((r) => ({
        bucket_start: this.formatDay(r.bucket_start),
        hours: Math.round(Number(r.hours) * 10) / 10,
        shifts: Number(r.shifts),
      })),
    };
  }

  async getEmployeeLoad(organizationId: string, query: QueryAnalyticsDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const rows: Array<{ employee_id: string; shifts: string; hours: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        'es.employee_id AS employee_id',
        'COUNT(*)::text AS shifts',
        `COALESCE(SUM(EXTRACT(EPOCH FROM (s.end_at - s.start_at)) / 3600.0), 0)::text AS hours`,
      ])
      .andWhere('es.employee_id IS NOT NULL')
      .andWhere(`UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}')`)
      .groupBy('es.employee_id')
      .orderBy('shifts', 'DESC')
      .getRawMany();

    if (rows.length === 0) return { range, employees: [] };

    const empNames = await this.loadEmployeeNameMap(rows.map((r) => r.employee_id));

    return {
      range,
      employees: rows.map((r) => ({
        employee_id: r.employee_id,
        name: this.lookupEmployeeName(empNames, r.employee_id),
        shifts: Number(r.shifts),
        hours: Math.round(Number(r.hours) * 10) / 10,
      })),
    };
  }

  async getDayDetail(organizationId: string, query: QueryDayDetailDto, userId: string) {
    await this.ensureAccess(organizationId, userId);

    // Validate the date is in an allowed (previous-month-or-earlier) window.
    const target = this.parseIsoDate(query.date);
    const now = new Date();
    const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    if (target >= currentMonthStart) {
      throw new BadRequestException('Day detail is only available for previous months.');
    }

    // Note: employees are loaded separately to avoid an alias collision —
    // TypeORM aliases `'user'` to a SQL reserved keyword, and on
    // multi-relation joins the user columns can silently fall out of the
    // hydrated row, leaving es.employee.user undefined for some entries.
    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .leftJoinAndSelect('es.shift', 's')
      .leftJoinAndSelect('es.station', 'station')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.room', 'room')
      .leftJoinAndSelect('es.bed', 'bed')
      .leftJoinAndSelect('es.chair', 'chair')
      .where('s.organization_id = :organizationId', { organizationId })
      .andWhere('es.scheduled_date = :date', { date: query.date });

    if (query.department_id) {
      qb.andWhere('es.department_id = :departmentId', { departmentId: query.department_id });
    }
    if (query.station_id) {
      qb.andWhere('es.station_id = :stationId', { stationId: query.station_id });
    }

    const rows = await qb.orderBy('s.start_at', 'ASC').getMany();
    const empDisplay = await this.loadEmployeeDisplayMap(rows.map((r) => r.employee_id));

    return {
      date: query.date,
      assignments: rows.map((es) => {
        const info = es.employee_id ? empDisplay.get(es.employee_id) : null;
        return {
          id: es.id,
          shift_id: es.shift_id,
          shift_name: es.shift?.name ?? es.shift?.shift_type ?? 'Shift',
          shift_type: es.shift?.shift_type ?? null,
          shift_start: es.shift?.start_at ?? null,
          shift_end: es.shift?.end_at ?? null,
          scheduled_date: es.scheduled_date,
          employee_id: es.employee_id,
          employee_name: info?.name ?? this.lookupEmployeeName(new Map(), es.employee_id),
          employee_role_name: info?.role_name ?? null,
          employee_role_code: info?.role_code ?? null,
          employee_position_title: info?.position_title ?? null,
          role: es.role ?? null,
          status: es.status ?? null,
          department_id: es.department_id,
          department_name: es.department?.name ?? null,
          station_id: es.station_id,
          station_name: es.station?.name ?? null,
          room_id: es.room_id,
          room_name: es.room?.name ?? null,
          bed_id: es.bed_id,
          bed_number: es.bed?.bed_number ?? null,
          chair_id: es.chair_id,
          chair_number: es.chair?.chair_number ?? null,
          actual_start_at: es.actual_start_at,
          actual_end_at: es.actual_end_at,
          notes: (es as { notes?: string | null }).notes ?? null,
        };
      }),
    };
  }

  // ──────────────────────── resource browse ──────────────────────────

  /**
   * One row per shift that produced at least one assignment in the range.
   * Stats are computed against the same ACTIVE_STATUSES set the KPI strip
   * uses, so a count here lines up with the KPIs above it.
   */
  async getShiftsBrowse(organizationId: string, query: QueryResourceBrowseDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const rows: Array<{
      shift_id: string;
      shift_name: string | null;
      shift_type: string | null;
      start_at: Date | string | null;
      end_at: Date | string | null;
      recurrence_type: string | null;
      total: string;
      filled: string;
      open: string;
      completed: string;
      unique_employees: string;
    }> = await this.buildBaseQuery(organizationId, range, query)
      .select([
        's.id AS shift_id',
        's.name AS shift_name',
        's.shift_type AS shift_type',
        's.start_at AS start_at',
        's.end_at AS end_at',
        's.recurrence_type AS recurrence_type',
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
        `SUM(CASE WHEN UPPER(es.status) IN ('DECLINED','REJECTED','CANCELLED') THEN 1 ELSE 0 END)::text AS open`,
        `SUM(CASE WHEN UPPER(es.status) = 'COMPLETED' THEN 1 ELSE 0 END)::text AS completed`,
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .groupBy('s.id, s.name, s.shift_type, s.start_at, s.end_at, s.recurrence_type')
      .orderBy('total', 'DESC')
      .getRawMany();

    return {
      range,
      shifts: rows.map((r) => ({
        shift_id: r.shift_id,
        shift_name: r.shift_name ?? r.shift_type ?? 'Shift',
        shift_type: r.shift_type,
        start_at: r.start_at,
        end_at: r.end_at,
        recurrence_type: r.recurrence_type,
        total_assignments: Number(r.total),
        filled: Number(r.filled),
        open: Number(r.open),
        completed: Number(r.completed),
        unique_employees: Number(r.unique_employees),
      })),
    };
  }

  /**
   * One row per active station in the org. Includes stations with zero
   * assignments so the user can see which ones are sitting idle — joined
   * via LEFT JOIN against the filtered employee_shifts subquery.
   */
  async getStationsBrowse(organizationId: string, query: QueryResourceBrowseDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const stationsQb = this.stationRepository
      .createQueryBuilder('st')
      .leftJoinAndSelect('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('st.is_active = true');

    if (query.department_id) {
      stationsQb.andWhere('st.department_id = :departmentId', { departmentId: query.department_id });
    }
    if (query.station_id) {
      stationsQb.andWhere('st.id = :stationId', { stationId: query.station_id });
    }

    const stations = await stationsQb.orderBy('st.sort_order', 'ASC').addOrderBy('st.name', 'ASC').getMany();

    const aggRows: Array<{
      station_id: string;
      total: string;
      filled: string;
      unique_employees: string;
    }> = await this.buildBaseQuery(organizationId, range, query)
      .select([
        'es.station_id AS station_id',
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .andWhere('es.station_id IS NOT NULL')
      .groupBy('es.station_id')
      .getRawMany();

    const aggByStation = new Map(aggRows.map((r) => [r.station_id, r]));

    const roomCounts: Array<{ station_id: string; rooms: string }> = await this.roomRepository
      .createQueryBuilder('r')
      .innerJoin('r.station', 'st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('r.is_active = true')
      .select(['r.station_id AS station_id', 'COUNT(*)::text AS rooms'])
      .groupBy('r.station_id')
      .getRawMany();

    const roomsByStation = new Map(roomCounts.map((r) => [r.station_id, Number(r.rooms)]));

    return {
      range,
      stations: stations.map((st) => {
        const agg = aggByStation.get(st.id);
        const required =
          (st.required_charge_nurses ?? 0) +
          (st.required_cnas ?? 0) +
          (st.required_sitters ?? 0) +
          (st.required_treatment_nurses ?? 0) +
          (st.required_nps ?? 0) +
          (st.required_mds ?? 0);
        return {
          station_id: st.id,
          station_name: st.name,
          department_id: st.department_id,
          department_name: (st as { department?: { name?: string } }).department?.name ?? null,
          required_staffing: required,
          room_count: roomsByStation.get(st.id) ?? 0,
          total_assignments: Number(agg?.total ?? 0),
          filled: Number(agg?.filled ?? 0),
          unique_employees: Number(agg?.unique_employees ?? 0),
        };
      }),
    };
  }

  async getRoomsBrowse(organizationId: string, query: QueryResourceBrowseDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const roomsQb = this.roomRepository
      .createQueryBuilder('r')
      .leftJoinAndSelect('r.station', 'st')
      .leftJoinAndSelect('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('r.is_active = true');

    if (query.department_id) {
      roomsQb.andWhere('st.department_id = :departmentId', { departmentId: query.department_id });
    }
    if (query.station_id) {
      roomsQb.andWhere('r.station_id = :stationId', { stationId: query.station_id });
    }
    if (query.room_id) {
      roomsQb.andWhere('r.id = :roomId', { roomId: query.room_id });
    }

    const rooms = await roomsQb
      .orderBy('st.name', 'ASC')
      .addOrderBy('r.sort_order', 'ASC')
      .addOrderBy('r.name', 'ASC')
      .getMany();

    const bedCounts: Array<{ room_id: string; beds: string }> = await this.bedRepository
      .createQueryBuilder('b')
      .innerJoin('b.room', 'r')
      .innerJoin('r.station', 'st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('b.is_active = true')
      .select(['b.room_id AS room_id', 'COUNT(*)::text AS beds'])
      .groupBy('b.room_id')
      .getRawMany();
    const bedsByRoom = new Map(bedCounts.map((r) => [r.room_id, Number(r.beds)]));

    const chairCounts: Array<{ room_id: string; chairs: string }> = await this.chairRepository
      .createQueryBuilder('c')
      .innerJoin('c.room', 'r')
      .innerJoin('r.station', 'st')
      .innerJoin('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('c.is_active = true')
      .select(['c.room_id AS room_id', 'COUNT(*)::text AS chairs'])
      .groupBy('c.room_id')
      .getRawMany();
    const chairsByRoom = new Map(chairCounts.map((r) => [r.room_id, Number(r.chairs)]));

    const aggRows: Array<{
      room_id: string;
      total: string;
      filled: string;
      unique_employees: string;
    }> = await this.buildBaseQuery(organizationId, range, query)
      .select([
        'es.room_id AS room_id',
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .andWhere('es.room_id IS NOT NULL')
      .groupBy('es.room_id')
      .getRawMany();
    const aggByRoom = new Map(aggRows.map((r) => [r.room_id, r]));

    return {
      range,
      rooms: rooms.map((r) => {
        const agg = aggByRoom.get(r.id);
        return {
          room_id: r.id,
          room_name: r.name,
          floor: r.floor,
          room_type: r.room_type,
          station_id: r.station_id,
          station_name: (r as { station?: { name?: string } }).station?.name ?? null,
          department_name:
            ((r as { station?: { department?: { name?: string } } }).station?.department?.name) ?? null,
          bed_count: bedsByRoom.get(r.id) ?? 0,
          chair_count: chairsByRoom.get(r.id) ?? 0,
          total_assignments: Number(agg?.total ?? 0),
          filled: Number(agg?.filled ?? 0),
          unique_employees: Number(agg?.unique_employees ?? 0),
        };
      }),
    };
  }

  async getBedsBrowse(organizationId: string, query: QueryResourceBrowseDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const bedsQb = this.bedRepository
      .createQueryBuilder('b')
      .leftJoinAndSelect('b.room', 'r')
      .leftJoinAndSelect('r.station', 'st')
      .leftJoinAndSelect('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('b.is_active = true');

    if (query.department_id) bedsQb.andWhere('st.department_id = :departmentId', { departmentId: query.department_id });
    if (query.station_id) bedsQb.andWhere('r.station_id = :stationId', { stationId: query.station_id });
    if (query.room_id) bedsQb.andWhere('b.room_id = :roomId', { roomId: query.room_id });
    if (query.bed_id) bedsQb.andWhere('b.id = :bedId', { bedId: query.bed_id });

    const beds = await bedsQb.orderBy('st.name', 'ASC').addOrderBy('r.name', 'ASC').addOrderBy('b.bed_number', 'ASC').getMany();

    const aggRows: Array<{ bed_id: string; total: string; unique_employees: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        'es.bed_id AS bed_id',
        'COUNT(*)::text AS total',
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .andWhere('es.bed_id IS NOT NULL')
      .groupBy('es.bed_id')
      .getRawMany();
    const aggByBed = new Map(aggRows.map((r) => [r.bed_id, r]));

    return {
      range,
      beds: beds.map((b) => {
        const agg = aggByBed.get(b.id);
        const room = (b as { room?: { name?: string; station?: { name?: string; department?: { name?: string } } } }).room;
        return {
          bed_id: b.id,
          bed_number: b.bed_number,
          room_id: b.room_id,
          room_name: room?.name ?? null,
          station_name: room?.station?.name ?? null,
          department_name: room?.station?.department?.name ?? null,
          total_assignments: Number(agg?.total ?? 0),
          unique_employees: Number(agg?.unique_employees ?? 0),
        };
      }),
    };
  }

  async getChairsBrowse(organizationId: string, query: QueryResourceBrowseDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const chairsQb = this.chairRepository
      .createQueryBuilder('c')
      .leftJoinAndSelect('c.room', 'r')
      .leftJoinAndSelect('r.station', 'st')
      .leftJoinAndSelect('st.department', 'dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('c.is_active = true');

    if (query.department_id) chairsQb.andWhere('st.department_id = :departmentId', { departmentId: query.department_id });
    if (query.station_id) chairsQb.andWhere('r.station_id = :stationId', { stationId: query.station_id });
    if (query.room_id) chairsQb.andWhere('c.room_id = :roomId', { roomId: query.room_id });
    if (query.chair_id) chairsQb.andWhere('c.id = :chairId', { chairId: query.chair_id });

    const chairs = await chairsQb
      .orderBy('st.name', 'ASC')
      .addOrderBy('r.name', 'ASC')
      .addOrderBy('c.chair_number', 'ASC')
      .getMany();

    const aggRows: Array<{ chair_id: string; total: string; unique_employees: string }> = await this
      .buildBaseQuery(organizationId, range, query)
      .select([
        'es.chair_id AS chair_id',
        'COUNT(*)::text AS total',
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .andWhere('es.chair_id IS NOT NULL')
      .groupBy('es.chair_id')
      .getRawMany();
    const aggByChair = new Map(aggRows.map((r) => [r.chair_id, r]));

    return {
      range,
      chairs: chairs.map((c) => {
        const agg = aggByChair.get(c.id);
        const room = (c as { room?: { name?: string; station?: { name?: string; department?: { name?: string } } } }).room;
        return {
          chair_id: c.id,
          chair_number: c.chair_number,
          room_id: c.room_id,
          room_name: room?.name ?? null,
          station_name: room?.station?.name ?? null,
          department_name: room?.station?.department?.name ?? null,
          total_assignments: Number(agg?.total ?? 0),
          unique_employees: Number(agg?.unique_employees ?? 0),
        };
      }),
    };
  }

  /**
   * Lists assignments for a single resource (shift / station / room / bed /
   * chair) within the analytics range. Reuses the same row shape as
   * day-detail so the UI can render them with the same component.
   */
  async getResourceAssignments(
    organizationId: string,
    query: QueryResourceAssignmentsDto,
    userId: string,
  ) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    // Same pattern as getDayDetail: load employees separately so the
    // user-name lookup can't be derailed by relation hydration quirks.
    const qb = this.employeeShiftRepository
      .createQueryBuilder('es')
      .leftJoinAndSelect('es.shift', 's')
      .leftJoinAndSelect('es.station', 'station')
      .leftJoinAndSelect('es.department', 'department')
      .leftJoinAndSelect('es.room', 'room')
      .leftJoinAndSelect('es.bed', 'bed')
      .leftJoinAndSelect('es.chair', 'chair')
      .where('s.organization_id = :organizationId', { organizationId })
      .andWhere('es.scheduled_date BETWEEN :from AND :to', { from: range.from, to: range.to });

    const filterColumn = this.resourceColumn(query.resource_type);
    qb.andWhere(`${filterColumn} = :resourceId`, { resourceId: query.resource_id });

    if (query.department_id) qb.andWhere('es.department_id = :departmentId', { departmentId: query.department_id });
    if (query.station_id) qb.andWhere('es.station_id = :stationId', { stationId: query.station_id });
    if (query.role) qb.andWhere('UPPER(es.role) = UPPER(:role)', { role: query.role });
    if (query.shift_type) qb.andWhere('UPPER(s.shift_type) = UPPER(:shiftType)', { shiftType: query.shift_type });

    const rows = await qb
      .orderBy('es.scheduled_date', 'DESC')
      .addOrderBy('s.start_at', 'ASC')
      .getMany();
    const empDisplay = await this.loadEmployeeDisplayMap(rows.map((r) => r.employee_id));

    return {
      range,
      resource_type: query.resource_type,
      resource_id: query.resource_id,
      assignments: rows.map((es) => {
        const info = es.employee_id ? empDisplay.get(es.employee_id) : null;
        return {
          id: es.id,
          scheduled_date: es.scheduled_date,
          shift_id: es.shift_id,
          shift_name: es.shift?.name ?? es.shift?.shift_type ?? 'Shift',
          shift_type: es.shift?.shift_type ?? null,
          shift_start: es.shift?.start_at ?? null,
          shift_end: es.shift?.end_at ?? null,
          employee_id: es.employee_id,
          employee_name: info?.name ?? this.lookupEmployeeName(new Map(), es.employee_id),
          employee_role_name: info?.role_name ?? null,
          employee_role_code: info?.role_code ?? null,
          employee_position_title: info?.position_title ?? null,
          role: es.role ?? null,
          status: es.status ?? null,
          department_id: es.department_id,
          department_name: es.department?.name ?? null,
          station_id: es.station_id,
          station_name: es.station?.name ?? null,
          room_id: es.room_id,
          room_name: es.room?.name ?? null,
          bed_id: es.bed_id,
          bed_number: es.bed?.bed_number ?? null,
          chair_id: es.chair_id,
          chair_number: es.chair?.chair_number ?? null,
          actual_start_at: es.actual_start_at,
          actual_end_at: es.actual_end_at,
          notes: (es as { notes?: string | null }).notes ?? null,
        };
      }),
    };
  }

  // ──────────────────── department deep-dive ────────────────────────

  /**
   * Lightweight list of departments for the explorer cards. Joins each
   * department's aggregate counts in a single query so the cards render
   * without follow-up round-trips.
   */
  async getDepartmentsBrowse(organizationId: string, query: QueryAnalyticsDto, userId: string) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    const departments = await this.departmentRepository
      .createQueryBuilder('dept')
      .where('dept.organization_id = :organizationId', { organizationId })
      .andWhere('dept.is_active = true')
      .orderBy('dept.sort_order', 'ASC')
      .addOrderBy('dept.name', 'ASC')
      .getMany();

    if (departments.length === 0) return { range, departments: [] };

    const aggRows: Array<{
      department_id: string;
      total: string;
      filled: string;
      open: string;
      completed: string;
      unique_employees: string;
      hours: string | null;
    }> = await this.buildBaseQuery(organizationId, range, query)
      .select([
        'es.department_id AS department_id',
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
        `SUM(CASE WHEN UPPER(es.status) IN ('DECLINED','REJECTED','CANCELLED') THEN 1 ELSE 0 END)::text AS open`,
        `SUM(CASE WHEN UPPER(es.status) = 'COMPLETED' THEN 1 ELSE 0 END)::text AS completed`,
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
        `COALESCE(SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN EXTRACT(EPOCH FROM (s.end_at - s.start_at)) / 3600.0 ELSE 0 END), 0)::text AS hours`,
      ])
      .andWhere('es.department_id IS NOT NULL')
      .groupBy('es.department_id')
      .getRawMany();

    const aggByDept = new Map(aggRows.map((r) => [r.department_id, r]));

    // Counts for stations / rooms / beds / chairs per dept — separate small
    // queries so we never fan out the assignment join over capacity tables.
    const stationCounts = await this.stationRepository
      .createQueryBuilder('st')
      .where('st.is_active = true')
      .andWhere('st.department_id IN (:...ids)', { ids: departments.map((d) => d.id) })
      .select(['st.department_id AS department_id', 'COUNT(*)::text AS stations'])
      .groupBy('st.department_id')
      .getRawMany<{ department_id: string; stations: string }>();
    const stationsByDept = new Map(stationCounts.map((r) => [r.department_id, Number(r.stations)]));

    const roomCounts = await this.roomRepository
      .createQueryBuilder('r')
      .innerJoin('r.station', 'st')
      .where('r.is_active = true')
      .andWhere('st.department_id IN (:...ids)', { ids: departments.map((d) => d.id) })
      .select(['st.department_id AS department_id', 'COUNT(*)::text AS rooms'])
      .groupBy('st.department_id')
      .getRawMany<{ department_id: string; rooms: string }>();
    const roomsByDept = new Map(roomCounts.map((r) => [r.department_id, Number(r.rooms)]));

    const bedCounts = await this.bedRepository
      .createQueryBuilder('b')
      .innerJoin('b.room', 'r')
      .innerJoin('r.station', 'st')
      .where('b.is_active = true')
      .andWhere('st.department_id IN (:...ids)', { ids: departments.map((d) => d.id) })
      .select(['st.department_id AS department_id', 'COUNT(*)::text AS beds'])
      .groupBy('st.department_id')
      .getRawMany<{ department_id: string; beds: string }>();
    const bedsByDept = new Map(bedCounts.map((r) => [r.department_id, Number(r.beds)]));

    const chairCounts = await this.chairRepository
      .createQueryBuilder('c')
      .innerJoin('c.room', 'r')
      .innerJoin('r.station', 'st')
      .where('c.is_active = true')
      .andWhere('st.department_id IN (:...ids)', { ids: departments.map((d) => d.id) })
      .select(['st.department_id AS department_id', 'COUNT(*)::text AS chairs'])
      .groupBy('st.department_id')
      .getRawMany<{ department_id: string; chairs: string }>();
    const chairsByDept = new Map(chairCounts.map((r) => [r.department_id, Number(r.chairs)]));

    return {
      range,
      departments: departments.map((d) => {
        const agg = aggByDept.get(d.id);
        return {
          department_id: d.id,
          department_name: d.name,
          department_type: d.department_type ?? null,
          code: d.code ?? null,
          station_count: stationsByDept.get(d.id) ?? 0,
          room_count: roomsByDept.get(d.id) ?? 0,
          bed_count: bedsByDept.get(d.id) ?? 0,
          chair_count: chairsByDept.get(d.id) ?? 0,
          total_assignments: Number(agg?.total ?? 0),
          filled: Number(agg?.filled ?? 0),
          open: Number(agg?.open ?? 0),
          completed: Number(agg?.completed ?? 0),
          unique_employees: Number(agg?.unique_employees ?? 0),
          total_hours: Math.round(Number(agg?.hours ?? 0) * 10) / 10,
        };
      }),
    };
  }

  /**
   * Big single-shot drill-down for one department. Returns the full
   * stations → rooms → beds/chairs hierarchy with assignment aggregates at
   * every level, plus shift + employee summaries scoped to the department.
   * Designed to power the comprehensive DepartmentDetailModal.
   */
  async getDepartmentOverview(
    organizationId: string,
    query: QueryDepartmentOverviewDto,
    userId: string,
  ) {
    await this.ensureAccess(organizationId, userId);
    const range = this.normalizeRange(query);

    // Department info (fail fast on bad id)
    const department = await this.departmentRepository.findOne({
      where: { id: query.department_id, organization_id: organizationId },
    });
    if (!department) {
      throw new BadRequestException('Department not found in this organization.');
    }

    // Scope every downstream query to this department by carrying it in the
    // filter set passed to buildBaseQuery / browse helpers.
    const scopedFilters: QueryAnalyticsDto = {
      ...query,
      department_id: query.department_id,
    };

    // ── stations + rooms + beds + chairs in this dept (full topology) ──
    const stations = await this.stationRepository
      .createQueryBuilder('st')
      .where('st.department_id = :deptId', { deptId: query.department_id })
      .andWhere('st.is_active = true')
      .orderBy('st.sort_order', 'ASC')
      .addOrderBy('st.name', 'ASC')
      .getMany();

    const stationIds = stations.map((s) => s.id);

    const rooms = stationIds.length
      ? await this.roomRepository
          .createQueryBuilder('r')
          .where('r.station_id IN (:...ids)', { ids: stationIds })
          .andWhere('r.is_active = true')
          .orderBy('r.sort_order', 'ASC')
          .addOrderBy('r.name', 'ASC')
          .getMany()
      : [];

    const roomIds = rooms.map((r) => r.id);

    const beds = roomIds.length
      ? await this.bedRepository
          .createQueryBuilder('b')
          .where('b.room_id IN (:...ids)', { ids: roomIds })
          .andWhere('b.is_active = true')
          .orderBy('b.bed_number', 'ASC')
          .getMany()
      : [];

    const chairs = roomIds.length
      ? await this.chairRepository
          .createQueryBuilder('c')
          .where('c.room_id IN (:...ids)', { ids: roomIds })
          .andWhere('c.is_active = true')
          .orderBy('c.chair_number', 'ASC')
          .getMany()
      : [];

    // ── Per-resource aggregates from employee_shifts ──
    const stationAgg = await this.aggregateByColumn(
      organizationId,
      range,
      scopedFilters,
      'es.station_id',
    );
    const roomAgg = await this.aggregateByColumn(
      organizationId,
      range,
      scopedFilters,
      'es.room_id',
    );
    const bedAgg = await this.aggregateByColumn(organizationId, range, scopedFilters, 'es.bed_id');
    const chairAgg = await this.aggregateByColumn(
      organizationId,
      range,
      scopedFilters,
      'es.chair_id',
    );

    // ── Shifts that produced any assignment in this dept's range ──
    const shiftRows: Array<{
      shift_id: string;
      shift_name: string | null;
      shift_type: string | null;
      start_at: Date | string | null;
      end_at: Date | string | null;
      recurrence_type: string | null;
      total: string;
      filled: string;
      open: string;
      completed: string;
      unique_employees: string;
    }> = await this.buildBaseQuery(organizationId, range, scopedFilters)
      .select([
        's.id AS shift_id',
        's.name AS shift_name',
        's.shift_type AS shift_type',
        's.start_at AS start_at',
        's.end_at AS end_at',
        's.recurrence_type AS recurrence_type',
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
        `SUM(CASE WHEN UPPER(es.status) IN ('DECLINED','REJECTED','CANCELLED') THEN 1 ELSE 0 END)::text AS open`,
        `SUM(CASE WHEN UPPER(es.status) = 'COMPLETED' THEN 1 ELSE 0 END)::text AS completed`,
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .groupBy('s.id, s.name, s.shift_type, s.start_at, s.end_at, s.recurrence_type')
      .orderBy('total', 'DESC')
      .getRawMany();

    // ── Employees who worked in this dept ──
    const employeeRows: Array<{
      employee_id: string;
      shifts: string;
      hours: string;
      filled: string;
    }> = await this.buildBaseQuery(organizationId, range, scopedFilters)
      .select([
        'es.employee_id AS employee_id',
        'COUNT(*)::text AS shifts',
        `COALESCE(SUM(EXTRACT(EPOCH FROM (s.end_at - s.start_at)) / 3600.0), 0)::text AS hours`,
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
      ])
      .andWhere('es.employee_id IS NOT NULL')
      .groupBy('es.employee_id')
      .orderBy('shifts', 'DESC')
      .getRawMany();

    const empDisplay = await this.loadEmployeeDisplayMap(
      employeeRows.map((r) => r.employee_id),
    );

    // ── Top-level stats ──
    const totalAssignments = shiftRows.reduce((acc, r) => acc + Number(r.total), 0);
    const totalFilled = shiftRows.reduce((acc, r) => acc + Number(r.filled), 0);
    const totalOpen = shiftRows.reduce((acc, r) => acc + Number(r.open), 0);
    const totalCompleted = shiftRows.reduce((acc, r) => acc + Number(r.completed), 0);
    const totalHours = employeeRows.reduce((acc, r) => acc + Number(r.hours), 0);
    const uniqueEmployeesGlobal = employeeRows.length;

    // ── Build the nested topology with aggregates baked in ──
    const bedsByRoom = new Map<string, typeof beds>();
    for (const b of beds) {
      const arr = bedsByRoom.get(b.room_id) ?? [];
      arr.push(b);
      bedsByRoom.set(b.room_id, arr);
    }
    const chairsByRoom = new Map<string, typeof chairs>();
    for (const c of chairs) {
      const arr = chairsByRoom.get(c.room_id) ?? [];
      arr.push(c);
      chairsByRoom.set(c.room_id, arr);
    }
    const roomsByStation = new Map<string, typeof rooms>();
    for (const r of rooms) {
      const arr = roomsByStation.get(r.station_id) ?? [];
      arr.push(r);
      roomsByStation.set(r.station_id, arr);
    }

    const stationsPayload = stations.map((st) => {
      const required =
        (st.required_charge_nurses ?? 0) +
        (st.required_cnas ?? 0) +
        (st.required_sitters ?? 0) +
        (st.required_treatment_nurses ?? 0) +
        (st.required_nps ?? 0) +
        (st.required_mds ?? 0);
      const stAgg = stationAgg.get(st.id);
      const stationRooms = roomsByStation.get(st.id) ?? [];
      return {
        station_id: st.id,
        station_name: st.name,
        location: st.location,
        required_staffing: required,
        total_assignments: Number(stAgg?.total ?? 0),
        filled: Number(stAgg?.filled ?? 0),
        unique_employees: Number(stAgg?.unique_employees ?? 0),
        rooms: stationRooms.map((r) => {
          const rAgg = roomAgg.get(r.id);
          const roomBeds = bedsByRoom.get(r.id) ?? [];
          const roomChairs = chairsByRoom.get(r.id) ?? [];
          return {
            room_id: r.id,
            room_name: r.name,
            floor: r.floor,
            room_type: r.room_type,
            bed_count: roomBeds.length,
            chair_count: roomChairs.length,
            total_assignments: Number(rAgg?.total ?? 0),
            filled: Number(rAgg?.filled ?? 0),
            unique_employees: Number(rAgg?.unique_employees ?? 0),
            beds: roomBeds.map((b) => {
              const bAgg = bedAgg.get(b.id);
              return {
                bed_id: b.id,
                bed_number: b.bed_number,
                total_assignments: Number(bAgg?.total ?? 0),
                filled: Number(bAgg?.filled ?? 0),
                unique_employees: Number(bAgg?.unique_employees ?? 0),
              };
            }),
            chairs: roomChairs.map((c) => {
              const cAgg = chairAgg.get(c.id);
              return {
                chair_id: c.id,
                chair_number: c.chair_number,
                total_assignments: Number(cAgg?.total ?? 0),
                filled: Number(cAgg?.filled ?? 0),
                unique_employees: Number(cAgg?.unique_employees ?? 0),
              };
            }),
          };
        }),
      };
    });

    return {
      range,
      department: {
        department_id: department.id,
        department_name: department.name,
        department_type: department.department_type ?? null,
        description: department.description ?? null,
      },
      stats: {
        total_shifts: shiftRows.length,
        total_assignments: totalAssignments,
        filled: totalFilled,
        open: totalOpen,
        completed: totalCompleted,
        unique_employees: uniqueEmployeesGlobal,
        station_count: stations.length,
        room_count: rooms.length,
        bed_count: beds.length,
        chair_count: chairs.length,
        total_hours: Math.round(totalHours * 10) / 10,
      },
      stations: stationsPayload,
      shifts: shiftRows.map((r) => ({
        shift_id: r.shift_id,
        shift_name: r.shift_name ?? r.shift_type ?? 'Shift',
        shift_type: r.shift_type,
        start_at: r.start_at,
        end_at: r.end_at,
        recurrence_type: r.recurrence_type,
        total_assignments: Number(r.total),
        filled: Number(r.filled),
        open: Number(r.open),
        completed: Number(r.completed),
        unique_employees: Number(r.unique_employees),
      })),
      employees: employeeRows.map((r) => {
        const info = empDisplay.get(r.employee_id);
        return {
          employee_id: r.employee_id,
          name: info?.name ?? `Employee ${r.employee_id.slice(0, 8)}`,
          role_name: info?.role_name ?? null,
          role_code: info?.role_code ?? null,
          shifts: Number(r.shifts),
          filled: Number(r.filled),
          hours: Math.round(Number(r.hours) * 10) / 10,
        };
      }),
    };
  }

  /**
   * Helper: aggregate employee_shifts by an arbitrary fk column (e.g.
   * `es.station_id`). Used by the department overview to compute
   * per-station / per-room / per-bed / per-chair counts in one pass each.
   */
  private async aggregateByColumn(
    organizationId: string,
    range: NormalizedRange,
    filters: QueryAnalyticsDto,
    column: string,
  ): Promise<Map<string, { total: string; filled: string; unique_employees: string }>> {
    const rows: Array<{
      key: string;
      total: string;
      filled: string;
      unique_employees: string;
    }> = await this.buildBaseQuery(organizationId, range, filters)
      .select([
        `${column} AS key`,
        'COUNT(*)::text AS total',
        `SUM(CASE WHEN UPPER(es.status) IN ('${ACTIVE_STATUSES.join("','")}') THEN 1 ELSE 0 END)::text AS filled`,
        'COUNT(DISTINCT es.employee_id)::text AS unique_employees',
      ])
      .andWhere(`${column} IS NOT NULL`)
      .groupBy(column)
      .getRawMany();
    return new Map(rows.map((r) => [r.key, { total: r.total, filled: r.filled, unique_employees: r.unique_employees }]));
  }

  private resourceColumn(type: AnalyticsResourceType): string {
    switch (type) {
      case 'shift':
        return 'es.shift_id';
      case 'station':
        return 'es.station_id';
      case 'room':
        return 'es.room_id';
      case 'bed':
        return 'es.bed_id';
      case 'chair':
        return 'es.chair_id';
    }
  }

  // ────────────────────────── helpers ────────────────────────────────

  private formatDay(value: string | Date): string {
    if (value instanceof Date) return this.toIsoDate(value);
    // Postgres returns "YYYY-MM-DD" or full timestamp depending on column type.
    const head = String(value).slice(0, 10);
    return /^\d{4}-\d{2}-\d{2}$/.test(head) ? head : this.toIsoDate(new Date(value));
  }

  /**
   * Resolves the best human-readable name for an Employee. Falls back through
   * multiple sources so the UI never has to render a literal "Unknown" if any
   * usable identifier exists in the database. Order:
   *   1. user.firstName + user.lastName  (canonical)
   *   2. user.displayName                (manually set, e.g. "Dr. Jane Smith")
   *   3. employee.position_title         (free-text job title)
   *   4. user.email local-part           (everything before "@")
   *   5. "Employee {first 8 of UUID}"    (last-resort, traceable)
   * Returns "Unassigned" only when there is no Employee record at all (open shift).
   */
  private resolveEmployeeName(
    emp:
      | {
          id?: string;
          position_title?: string | null;
          user?: {
            firstName?: string | null;
            lastName?: string | null;
            displayName?: string | null;
            email?: string | null;
          } | null;
        }
      | null
      | undefined,
  ): string {
    if (!emp) return 'Unassigned';
    const user = emp.user ?? null;
    const firstLast = [user?.firstName, user?.lastName]
      .filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
      .map((p) => p.trim())
      .join(' ')
      .trim();
    if (firstLast) return firstLast;
    if (user?.displayName && user.displayName.trim()) return user.displayName.trim();
    if (emp.position_title && emp.position_title.trim()) return emp.position_title.trim();
    if (user?.email) {
      const local = user.email.split('@')[0];
      if (local) return local;
    }
    if (emp.id) return `Employee ${emp.id.slice(0, 8)}`;
    return 'Unknown';
  }

  /**
   * Pre-loads display info for a batch of employee ids — name, role, and
   * position title — keyed by employee_id. Uses a pure parameterized SQL
   * query (no QueryBuilder, no relation hydration) so the result can't be
   * derailed by TypeORM aliasing or `select: false` quirks. Joins both
   * `users` and `provider_roles` so a single round-trip serves every
   * downstream resolution site (day-detail, resource-assignments,
   * department overview, employee load).
   */
  private async loadEmployeeDisplayMap(
    employeeIds: Array<string | null | undefined>,
  ): Promise<Map<string, EmployeeDisplayInfo>> {
    const ids = Array.from(new Set(employeeIds.filter((v): v is string => !!v)));
    if (ids.length === 0) return new Map();

    const sql = `
      SELECT
        e.id AS id,
        e.position_title AS position_title,
        u."firstName" AS first_name,
        u."lastName" AS last_name,
        u."displayName" AS display_name,
        u.email AS email,
        pr.name AS role_name,
        pr.code AS role_code
      FROM employees e
      LEFT JOIN users u ON u.id = e.user_id
      LEFT JOIN provider_roles pr ON pr.id = e.provider_role_id
      WHERE e.id = ANY($1::uuid[])
    `;
    const rows: Array<{
      id: string;
      position_title: string | null;
      first_name: string | null;
      last_name: string | null;
      display_name: string | null;
      email: string | null;
      role_name: string | null;
      role_code: string | null;
    }> = await this.employeeRepository.query(sql, [ids]);

    const map = new Map<string, EmployeeDisplayInfo>();
    for (const r of rows) {
      const name = this.resolveEmployeeName({
        id: r.id,
        position_title: r.position_title,
        user: {
          firstName: r.first_name,
          lastName: r.last_name,
          displayName: r.display_name,
          email: r.email,
        },
      });
      map.set(r.id, {
        id: r.id,
        name,
        role_name: r.role_name,
        role_code: r.role_code,
        position_title: r.position_title,
      });
    }
    return map;
  }

  /**
   * Thin name-only adapter over `loadEmployeeDisplayMap` for callers that
   * don't need role/position info. Same data source, same fallbacks.
   */
  private async loadEmployeeNameMap(
    employeeIds: Array<string | null | undefined>,
  ): Promise<Map<string, string>> {
    const display = await this.loadEmployeeDisplayMap(employeeIds);
    const out = new Map<string, string>();
    for (const [id, info] of display) out.set(id, info.name);
    return out;
  }

  /** Resolves a single employee_id against a name map, with safe fallback. */
  private lookupEmployeeName(
    map: Map<string, string>,
    employeeId: string | null | undefined,
  ): string {
    if (!employeeId) return 'Unassigned';
    return map.get(employeeId) ?? `Employee ${employeeId.slice(0, 8)}`;
  }
}
