import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../../employees/entities/employee.entity';
import { AvailabilityRule } from '../../../employees/calendar/entities/availability-rule.entity';
// ── Types (previously in fixture file, now defined inline) ───────────────

export type AvailabilityType = 'specific' | 'recurring';
export type AvailabilityStatus = 'available' | 'unavailable' | 'tentative' | 'booked';
export type WeekdayCode = 'MON' | 'TUE' | 'WED' | 'THU' | 'FRI' | 'SAT' | 'SUN';

export interface EmployeeAvailabilityRecord {
  id: string;
  employee_id: string;
  organization_id: string | null;
  availability_type: AvailabilityType;
  date: string | null;
  recurring_start_date: string | null;
  recurring_end_date: string | null;
  days_of_week: WeekdayCode[] | null;
  start_time: string;
  end_time: string;
  status: AvailabilityStatus;
  max_bookings: number;
  current_bookings: number;
  notes: string | null;
}

export interface FindAvailabilityFilters {
  employeeId?: string;
  organizationId?: string;
  date?: string;
  startTime?: string;
  endTime?: string;
  status?: string;
}

export interface SearchAvailableEmployeesParams {
  date: string;
  startTime: string;
  endTime: string;
  organizationId?: string;
  maxResults?: number;
}

export interface ScheduleParams {
  employeeId: string;
  startDate?: string;
  endDate?: string;
}

const WEEKDAY_BY_INDEX: WeekdayCode[] = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

@Injectable()
export class EmployeeAvailabilityService {
  private readonly logger = new Logger(EmployeeAvailabilityService.name);

  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(AvailabilityRule)
    private readonly availabilityRuleRepository: Repository<AvailabilityRule>,
  ) {}

  /**
   * Convert an AvailabilityRule (DB row keyed by user_id + day_of_week)
   * into the EmployeeAvailabilityRecord shape the MCP tools expect.
   *
   * Rules with a non-null `date` column are specific-date availability;
   * rules with `date IS NULL` are recurring weekly rules.
   */
  private ruleToRecord(
    rule: AvailabilityRule,
    employeeId: string,
    organizationId: string | null,
  ): EmployeeAvailabilityRecord {
    const isSpecific = !!rule.date;
    const dayCode = rule.day_of_week != null
      ? (WEEKDAY_BY_INDEX[rule.day_of_week] ?? 'MON')
      : 'MON';

    const dateStr = rule.date
      ? (typeof rule.date === 'string'
          ? rule.date.slice(0, 10)
          : new Date(rule.date).toISOString().slice(0, 10))
      : null;

    return {
      id: rule.id,
      employee_id: employeeId,
      organization_id: organizationId,
      availability_type: isSpecific ? 'specific' : 'recurring',
      date: dateStr,
      recurring_start_date: rule.effective_from
        ? new Date(rule.effective_from).toISOString().slice(0, 10)
        : null,
      recurring_end_date: rule.effective_until
        ? new Date(rule.effective_until).toISOString().slice(0, 10)
        : null,
      days_of_week: isSpecific ? null : [dayCode],
      start_time: typeof rule.start_time === 'string'
        ? rule.start_time.slice(0, 5)
        : rule.start_time,
      end_time: typeof rule.end_time === 'string'
        ? rule.end_time.slice(0, 5)
        : rule.end_time,
      status: rule.is_available ? 'available' : 'unavailable',
      max_bookings: 1,
      current_bookings: 0,
      notes: rule.shift_type ?? null,
    };
  }

  /**
   * Load availability rules from the DB for a given employee.
   */
  private async loadAvailabilityForEmployee(
    employeeId: string,
    organizationId?: string,
  ): Promise<EmployeeAvailabilityRecord[]> {
    // Validate UUID format to prevent DB errors from LLM-invented IDs
    if (!UUID_REGEX.test(employeeId)) return [];

    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId },
      select: ['id', 'user_id', 'organization_id'],
    });
    if (!employee) return [];

    const qb = this.availabilityRuleRepository
      .createQueryBuilder('r')
      .where('r.user_id = :userId', { userId: employee.user_id });

    if (organizationId) {
      qb.andWhere(
        '(r.organization_id = :orgId OR r.organization_id IS NULL)',
        { orgId: organizationId },
      );
    }

    qb.orderBy('r.day_of_week', 'ASC').addOrderBy('r.start_time', 'ASC');
    const rules = await qb.getMany();

    return rules.map((rule) =>
      this.ruleToRecord(rule, employeeId, organizationId ?? employee.organization_id),
    );
  }

  /**
   * Load availability for all employees in an organization.
   * Queries availability_rules directly by organization_id, then resolves
   * user_id → employee_id via a reverse lookup on the employees table.
   */
  private async loadAvailabilityForOrg(
    organizationId: string,
  ): Promise<EmployeeAvailabilityRecord[]> {
    // 1. Query availability_rules directly by organization_id
    const rules = await this.availabilityRuleRepository
      .createQueryBuilder('r')
      .where('r.organization_id = :orgId', { orgId: organizationId })
      .orderBy('r.day_of_week', 'ASC')
      .addOrderBy('r.start_time', 'ASC')
      .getMany();

    this.logger.debug(
      `loadAvailabilityForOrg(${organizationId}): found ${rules.length} availability_rules`,
    );

    if (rules.length === 0) return [];

    // 2. Collect distinct user_ids from the rules and resolve to employee_ids
    const ruleUserIds = [...new Set(rules.map((r) => r.user_id))];
    const employees = await this.employeeRepository.find({
      where: ruleUserIds.map((uid) => ({ user_id: uid, organization_id: organizationId })),
      select: ['id', 'user_id'],
    });

    // Build user_id → employee_id map
    const userToEmployee = new Map(employees.map((e) => [e.user_id, e.id]));

    this.logger.debug(
      `loadAvailabilityForOrg: ${ruleUserIds.length} user_ids in rules, ${employees.length} matched employees`,
    );

    return rules.map((rule) => {
      const employeeId = userToEmployee.get(rule.user_id) ?? rule.user_id;
      return this.ruleToRecord(rule, employeeId, organizationId);
    });
  }

  // ── Public API ─────────────────────────────────────────────────────────

  async findAvailability(
    filters: FindAvailabilityFilters,
  ): Promise<EmployeeAvailabilityRecord[]> {
    let records: EmployeeAvailabilityRecord[] = [];

    if (filters.employeeId) {
      records = await this.loadAvailabilityForEmployee(
        filters.employeeId,
        filters.organizationId,
      );
    } else if (filters.organizationId) {
      records = await this.loadAvailabilityForOrg(filters.organizationId);
    }

    return this.applyFilters(records, filters);
  }

  async searchAvailableEmployees(
    params: SearchAvailableEmployeesParams,
  ): Promise<EmployeeAvailabilityRecord[]> {
    const { date, startTime, endTime, organizationId, maxResults = 10 } = params;

    let allRecords: EmployeeAvailabilityRecord[] = [];
    if (organizationId) {
      allRecords = await this.loadAvailabilityForOrg(organizationId);
    }

    const filters: FindAvailabilityFilters = {
      organizationId,
      date,
      startTime,
      endTime,
      status: 'available',
    };

    const filtered = this.applyFilters(allRecords, filters).filter(
      (slot) => slot.current_bookings < slot.max_bookings,
    );

    // Deduplicate by employee_id, take first match per employee
    const matches: EmployeeAvailabilityRecord[] = [];
    const seenEmployees = new Set<string>();
    for (const slot of filtered) {
      if (seenEmployees.has(slot.employee_id)) continue;
      matches.push(slot);
      seenEmployees.add(slot.employee_id);
      if (matches.length >= maxResults) break;
    }

    return matches;
  }

  async getEmployeeSchedule(
    params: ScheduleParams,
  ): Promise<EmployeeAvailabilityRecord[]> {
    const { employeeId, startDate, endDate } = params;

    // Validate UUID to prevent DB errors from LLM-invented IDs
    if (!UUID_REGEX.test(employeeId)) return [];

    const records = await this.loadAvailabilityForEmployee(employeeId);

    return records.filter((slot) => {
      // Recurring rules always apply (they repeat every week)
      if (slot.availability_type === 'recurring') return true;
      // Specific-date rules: filter by date range
      if (!slot.date) return false;
      if (startDate && slot.date < startDate) return false;
      if (endDate && slot.date > endDate) return false;
      return true;
    });
  }

  // ── Private helpers ────────────────────────────────────────────────────

  private applyFilters(
    records: EmployeeAvailabilityRecord[],
    filters: FindAvailabilityFilters,
  ): EmployeeAvailabilityRecord[] {
    return records.filter((slot) => {
      if (
        filters.organizationId &&
        slot.organization_id &&
        slot.organization_id !== filters.organizationId
      ) {
        return false;
      }
      if (filters.status && slot.status !== filters.status) return false;

      if (filters.date) {
        const matchesDate =
          slot.availability_type === 'recurring'
            ? this.recurringMatchesDate(slot, filters.date)
            : slot.date === filters.date;
        if (!matchesDate) return false;
      }

      if (filters.startTime && slot.start_time > filters.startTime) return false;
      if (filters.endTime && slot.end_time < filters.endTime) return false;

      return true;
    });
  }

  private recurringMatchesDate(
    slot: EmployeeAvailabilityRecord,
    dateStr: string,
  ): boolean {
    if (slot.recurring_start_date && dateStr < slot.recurring_start_date) return false;
    if (slot.recurring_end_date && dateStr > slot.recurring_end_date) return false;
    if (!slot.days_of_week || slot.days_of_week.length === 0) return true;

    const day = WEEKDAY_BY_INDEX[new Date(`${dateStr}T00:00:00Z`).getUTCDay()];
    return slot.days_of_week.includes(day);
  }
}
