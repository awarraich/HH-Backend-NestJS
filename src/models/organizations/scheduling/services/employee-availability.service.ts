import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../../employees/entities/employee.entity';
import {
  DEMO_AVAILABILITY_FIXTURE,
  EmployeeAvailabilityRecord,
  WeekdayCode,
  generateAvailabilityForEmployee,
} from '../fixtures/employee-availability.fixture';

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

@Injectable()
export class EmployeeAvailabilityService {
  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
  ) {}

  findAvailability(filters: FindAvailabilityFilters): EmployeeAvailabilityRecord[] {
    const source = this.resolveSource(filters.employeeId, filters.organizationId);
    return this.applyFilters(source, filters);
  }

  async searchAvailableEmployees(
    params: SearchAvailableEmployeesParams,
  ): Promise<EmployeeAvailabilityRecord[]> {
    const { date, startTime, endTime, organizationId, maxResults = 10 } = params;

    const candidates = await this.loadCandidatePool(organizationId);
    const filters: FindAvailabilityFilters = {
      organizationId,
      date,
      startTime,
      endTime,
      status: 'available',
    };

    const matches: EmployeeAvailabilityRecord[] = [];
    const seenEmployees = new Set<string>();

    for (const employeeId of candidates) {
      if (seenEmployees.has(employeeId)) continue;
      const slots = this.applyFilters(
        generateAvailabilityForEmployee(employeeId, organizationId ?? null),
        filters,
      ).filter((slot) => slot.current_bookings < slot.max_bookings);

      if (slots.length > 0) {
        matches.push(slots[0]);
        seenEmployees.add(employeeId);
      }
      if (matches.length >= maxResults) break;
    }

    return matches;
  }

  getEmployeeSchedule(params: ScheduleParams): EmployeeAvailabilityRecord[] {
    const { employeeId, startDate, endDate } = params;
    const records = this.resolveSource(employeeId);

    return records.filter((slot) => {
      if (slot.availability_type === 'recurring') return true;
      if (!slot.date) return false;
      if (startDate && slot.date < startDate) return false;
      if (endDate && slot.date > endDate) return false;
      return true;
    });
  }

  private resolveSource(
    employeeId?: string,
    organizationId?: string,
  ): EmployeeAvailabilityRecord[] {
    if (employeeId) {
      const seeded = DEMO_AVAILABILITY_FIXTURE.filter((r) => r.employee_id === employeeId);
      if (seeded.length > 0) return seeded;
      return generateAvailabilityForEmployee(employeeId, organizationId ?? null);
    }
    if (organizationId) {
      return DEMO_AVAILABILITY_FIXTURE.filter((r) => r.organization_id === organizationId);
    }
    return DEMO_AVAILABILITY_FIXTURE;
  }

  private applyFilters(
    records: EmployeeAvailabilityRecord[],
    filters: FindAvailabilityFilters,
  ): EmployeeAvailabilityRecord[] {
    return records.filter((slot) => {
      if (filters.organizationId && slot.organization_id && slot.organization_id !== filters.organizationId) {
        return false;
      }
      if (filters.status && slot.status !== filters.status) return false;

      if (filters.date) {
        const matchesDate = slot.availability_type === 'recurring'
          ? this.recurringMatchesDate(slot, filters.date)
          : slot.date === filters.date;
        if (!matchesDate) return false;
      }

      if (filters.startTime && slot.start_time > filters.startTime) return false;
      if (filters.endTime && slot.end_time < filters.endTime) return false;

      return true;
    });
  }

  private recurringMatchesDate(slot: EmployeeAvailabilityRecord, dateStr: string): boolean {
    if (slot.recurring_start_date && dateStr < slot.recurring_start_date) return false;
    if (slot.recurring_end_date && dateStr > slot.recurring_end_date) return false;
    if (!slot.days_of_week || slot.days_of_week.length === 0) return true;

    const day = WEEKDAY_BY_INDEX[new Date(`${dateStr}T00:00:00Z`).getUTCDay()];
    return slot.days_of_week.includes(day);
  }

  private async loadCandidatePool(organizationId?: string): Promise<string[]> {
    if (!organizationId) {
      return DEMO_AVAILABILITY_FIXTURE.map((r) => r.employee_id);
    }
    const employees = await this.employeeRepository.find({
      where: { organization_id: organizationId },
      select: ['id'],
      take: 50,
    });
    if (employees.length > 0) return employees.map((e) => e.id);
    return DEMO_AVAILABILITY_FIXTURE
      .filter((r) => r.organization_id === organizationId)
      .map((r) => r.employee_id);
  }
}
