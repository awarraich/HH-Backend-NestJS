import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Employee } from '../../entities/employee.entity';
import { ScheduledTaskAssignment } from '../../../organizations/scheduling/entities/scheduled-task-assignment.entity';
import { QueryMyScheduledWorkDto } from '../dto/query-my-scheduled-work.dto';

export interface MyScheduledWorkRow {
  id: string;
  task_type_code: string;
  status: string;
  priority: number;
  scheduled_start_at: string;
  scheduled_end_at: string;
  organization_id: string;
  organization_name: string | null;
  subject_name: string | null;
  subject_phone: string | null;
  subject_address: string | null;
  notes: string | null;
  details: Record<string, unknown>;
  location: {
    department_id: string | null;
    station_id: string | null;
    room_id: string | null;
    bed_id: string | null;
    chair_id: string | null;
    zone_id: string | null;
    fleet_vehicle_id: string | null;
    lab_workstation_id: string | null;
    shift_id: string | null;
  };
  assignment: {
    id: string;
    employee_id: string;
    assignment_role: string;
    is_primary: boolean;
    /** Per-employee response state on this assignment ('PENDING' |
     *  'CONFIRMED' | 'DECLINED'). Independent of the task's lifecycle
     *  status — see ScheduledTaskAssignment.status for details. */
    status: string;
  };
}

function toIso(d: Date | string | null | undefined): string {
  if (!d) return '';
  if (d instanceof Date) return d.toISOString();
  return new Date(d).toISOString();
}

/**
 * Aggregates every "scheduled task" the logged-in user is assigned to —
 * clinic appointments, field visits, transport trips, pharmacy prescriptions
 * — across all of their employee records (multi-org). The org portal writes
 * each of these to a single `scheduled_tasks` table with a `task_type_code`
 * discriminator, so one query covers all org-type-specific work without a
 * fan-out.
 *
 * This is the bridge the employee CalendarTab needed: org-portal-created
 * appointments now reach the employee UI.
 */
@Injectable()
export class MyScheduledWorkService {
  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(ScheduledTaskAssignment)
    private readonly assignmentRepository: Repository<ScheduledTaskAssignment>,
  ) {}

  private async getMyEmployeeIds(userId: string): Promise<string[]> {
    const rows = await this.employeeRepository.find({
      where: { user_id: userId },
      select: ['id'],
    });
    return rows.map((r) => r.id);
  }

  async findMine(
    userId: string,
    query: QueryMyScheduledWorkDto,
  ): Promise<{ data: MyScheduledWorkRow[]; total: number; page: number; limit: number }> {
    const { page = 1, limit = 200, from_date, to_date, organization_id, task_type_code, status } = query;
    const employeeIds = await this.getMyEmployeeIds(userId);
    if (employeeIds.length === 0) {
      return { data: [], total: 0, page, limit };
    }

    const qb = this.assignmentRepository
      .createQueryBuilder('a')
      .innerJoinAndSelect('a.scheduledTask', 't')
      .leftJoinAndSelect('t.organization', 'organization')
      .where('a.employee_id IN (:...employeeIds)', { employeeIds })
      .andWhere('t.deleted_at IS NULL');

    if (organization_id) qb.andWhere('t.organization_id = :organization_id', { organization_id });
    if (task_type_code) qb.andWhere('t.task_type_code = :task_type_code', { task_type_code });
    if (status) qb.andWhere('t.status = :status', { status });
    if (from_date) qb.andWhere('t.scheduled_start_at >= :from_date', { from_date: `${from_date}T00:00:00Z` });
    if (to_date) qb.andWhere('t.scheduled_start_at <= :to_date', { to_date: `${to_date}T23:59:59Z` });

    qb.orderBy('t.scheduled_start_at', 'ASC')
      .skip((page - 1) * limit)
      .take(limit);

    const [rows, total] = await qb.getManyAndCount();

    const data: MyScheduledWorkRow[] = rows.map((a) => {
      const t = a.scheduledTask;
      return {
        id: t.id,
        task_type_code: t.task_type_code,
        status: t.status,
        priority: t.priority,
        scheduled_start_at: toIso(t.scheduled_start_at),
        scheduled_end_at: toIso(t.scheduled_end_at),
        organization_id: t.organization_id,
        organization_name: t.organization?.organization_name ?? null,
        subject_name: t.subject_name,
        subject_phone: t.subject_phone,
        subject_address: t.subject_address,
        notes: t.notes,
        details: t.details ?? {},
        location: {
          department_id: t.department_id,
          station_id: t.station_id,
          room_id: t.room_id,
          bed_id: t.bed_id,
          chair_id: t.chair_id,
          zone_id: t.zone_id,
          fleet_vehicle_id: t.fleet_vehicle_id,
          lab_workstation_id: t.lab_workstation_id,
          shift_id: t.shift_id,
        },
        assignment: {
          id: a.id,
          employee_id: a.employee_id,
          assignment_role: a.assignment_role,
          is_primary: a.is_primary,
          status: a.status,
        },
      };
    });

    return { data, total, page, limit };
  }

  /**
   * Employee accepts or declines an assignment. Mirrors `MyShiftsService.respond`
   * — verifies the assignment belongs to one of the user's Employee records,
   * flips `status` to 'CONFIRMED' or 'DECLINED', and returns the updated row
   * in the same shape `findMine` produces so the frontend can swap entries
   * without a refetch.
   */
  async respond(
    userId: string,
    assignmentId: string,
    accept: boolean,
  ): Promise<MyScheduledWorkRow> {
    const assignment = await this.assignmentRepository.findOne({
      where: { id: assignmentId },
      relations: ['scheduledTask', 'scheduledTask.organization', 'employee'],
    });
    if (!assignment) throw new NotFoundException('Assignment not found');
    if (!assignment.employee || assignment.employee.user_id !== userId) {
      throw new ForbiddenException('You can only respond to your own assignments.');
    }

    assignment.status = accept ? 'CONFIRMED' : 'DECLINED';
    const saved = await this.assignmentRepository.save(assignment);
    const t = saved.scheduledTask;
    return {
      id: t.id,
      task_type_code: t.task_type_code,
      status: t.status,
      priority: t.priority,
      scheduled_start_at: toIso(t.scheduled_start_at),
      scheduled_end_at: toIso(t.scheduled_end_at),
      organization_id: t.organization_id,
      organization_name: t.organization?.organization_name ?? null,
      subject_name: t.subject_name,
      subject_phone: t.subject_phone,
      subject_address: t.subject_address,
      notes: t.notes,
      details: t.details ?? {},
      location: {
        department_id: t.department_id,
        station_id: t.station_id,
        room_id: t.room_id,
        bed_id: t.bed_id,
        chair_id: t.chair_id,
        zone_id: t.zone_id,
        fleet_vehicle_id: t.fleet_vehicle_id,
        lab_workstation_id: t.lab_workstation_id,
        shift_id: t.shift_id,
      },
      assignment: {
        id: saved.id,
        employee_id: saved.employee_id,
        assignment_role: saved.assignment_role,
        is_primary: saved.is_primary,
        status: saved.status,
      },
    };
  }
}
