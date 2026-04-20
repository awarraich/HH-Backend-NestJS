import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, IsNull, DataSource } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { ScheduledTask } from '../entities/scheduled-task.entity';
import { ScheduledTaskAssignment } from '../entities/scheduled-task-assignment.entity';
import { ScheduledTaskStatusHistory } from '../entities/scheduled-task-status-history.entity';
import { SchedulingTaskType } from '../entities/scheduling-task-type.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { Room } from '../entities/room.entity';
import { Zone } from '../entities/zone.entity';
import { FleetVehicle } from '../entities/fleet-vehicle.entity';
import { LabWorkstation } from '../entities/lab-workstation.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import {
  CreateScheduledTaskBase,
  UpdateScheduledTaskBase,
  QueryScheduledTaskBase,
  TransitionScheduledTaskStatusDto,
  CreateScheduledTaskAssignmentDto,
} from '../dto/scheduled-task-base.dto';

@Injectable()
export class ScheduledTaskService {
  constructor(
    @InjectRepository(ScheduledTask)
    private readonly taskRepository: Repository<ScheduledTask>,
    @InjectRepository(ScheduledTaskAssignment)
    private readonly assignmentRepository: Repository<ScheduledTaskAssignment>,
    @InjectRepository(ScheduledTaskStatusHistory)
    private readonly historyRepository: Repository<ScheduledTaskStatusHistory>,
    @InjectRepository(SchedulingTaskType)
    private readonly taskTypeRepository: Repository<SchedulingTaskType>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
    @InjectRepository(Station)
    private readonly stationRepository: Repository<Station>,
    @InjectRepository(Room)
    private readonly roomRepository: Repository<Room>,
    @InjectRepository(Zone)
    private readonly zoneRepository: Repository<Zone>,
    @InjectRepository(FleetVehicle)
    private readonly fleetVehicleRepository: Repository<FleetVehicle>,
    @InjectRepository(LabWorkstation)
    private readonly labWorkstationRepository: Repository<LabWorkstation>,
    private readonly organizationRoleService: OrganizationRoleService,
    private readonly dataSource: DataSource,
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

  private async getTaskType(code: string): Promise<SchedulingTaskType> {
    const type = await this.taskTypeRepository.findOne({ where: { code, is_active: true } });
    if (!type) throw new BadRequestException(`Unknown or inactive task type: ${code}`);
    return type;
  }

  private async validateResourcesInOrg(
    organizationId: string,
    refs: {
      department_id?: string | null;
      station_id?: string | null;
      room_id?: string | null;
      zone_id?: string | null;
      fleet_vehicle_id?: string | null;
      lab_workstation_id?: string | null;
    },
  ): Promise<void> {
    if (refs.department_id) {
      const dept = await this.departmentRepository.findOne({
        where: { id: refs.department_id, organization_id: organizationId },
      });
      if (!dept) throw new BadRequestException('Invalid department for this organization');
    }
    if (refs.station_id) {
      const station = await this.stationRepository.findOne({
        where: { id: refs.station_id },
        relations: ['department'],
      });
      if (!station || station.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid station for this organization');
      }
    }
    if (refs.room_id) {
      const room = await this.roomRepository.findOne({
        where: { id: refs.room_id },
        relations: ['station', 'station.department'],
      });
      if (!room || room.station.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid room for this organization');
      }
    }
    if (refs.zone_id) {
      const zone = await this.zoneRepository.findOne({
        where: { id: refs.zone_id },
        relations: ['department'],
      });
      if (!zone || zone.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid zone for this organization');
      }
    }
    if (refs.fleet_vehicle_id) {
      const v = await this.fleetVehicleRepository.findOne({
        where: { id: refs.fleet_vehicle_id },
        relations: ['department'],
      });
      if (!v || v.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid fleet vehicle for this organization');
      }
    }
    if (refs.lab_workstation_id) {
      const w = await this.labWorkstationRepository.findOne({
        where: { id: refs.lab_workstation_id },
        relations: ['department'],
      });
      if (!w || w.department.organization_id !== organizationId) {
        throw new BadRequestException('Invalid lab workstation for this organization');
      }
    }
  }

  private validateStatusAgainstType(type: SchedulingTaskType, status: string): void {
    const allowed = type.default_statuses?.allowed;
    if (Array.isArray(allowed) && allowed.length > 0 && !allowed.includes(status)) {
      throw new BadRequestException(
        `Status "${status}" is not allowed for task type "${type.code}". Allowed: ${allowed.join(', ')}`,
      );
    }
  }

  async list(
    organizationId: string,
    taskTypeCode: string,
    query: QueryScheduledTaskBase,
    userId: string,
  ): Promise<{ data: ScheduledTask[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    await this.getTaskType(taskTypeCode);

    const page = query.page ?? 1;
    const limit = query.limit ?? 50;
    const skip = (page - 1) * limit;

    const qb = this.taskRepository
      .createQueryBuilder('t')
      .leftJoinAndSelect('t.assignments', 'a')
      .leftJoinAndSelect('a.employee', 'a_emp')
      .leftJoinAndSelect('a_emp.user', 'a_emp_user')
      .leftJoinAndSelect('a_emp.providerRole', 'a_emp_role')
      .leftJoinAndSelect('t.department', 'department')
      .leftJoinAndSelect('t.station', 'station')
      .leftJoinAndSelect('t.room', 'room')
      .leftJoinAndSelect('t.zone', 'zone')
      .leftJoinAndSelect('t.fleetVehicle', 'fleetVehicle')
      .leftJoinAndSelect('t.labWorkstation', 'labWorkstation')
      .where('t.organization_id = :organizationId', { organizationId })
      .andWhere('t.task_type_code = :taskTypeCode', { taskTypeCode })
      .andWhere('t.deleted_at IS NULL');

    if (query.from_date) {
      qb.andWhere('t.scheduled_start_at >= :fromDate', {
        fromDate: `${query.from_date}T00:00:00`,
      });
    }
    if (query.to_date) {
      qb.andWhere('t.scheduled_start_at <= :toDate', {
        toDate: `${query.to_date}T23:59:59.999`,
      });
    }
    if (query.status) qb.andWhere('t.status = :status', { status: query.status });
    if (query.department_id) qb.andWhere('t.department_id = :deptId', { deptId: query.department_id });
    if (query.station_id) qb.andWhere('t.station_id = :stationId', { stationId: query.station_id });
    if (query.room_id) qb.andWhere('t.room_id = :roomId', { roomId: query.room_id });
    if (query.zone_id) qb.andWhere('t.zone_id = :zoneId', { zoneId: query.zone_id });
    if (query.fleet_vehicle_id) {
      qb.andWhere('t.fleet_vehicle_id = :vehicleId', { vehicleId: query.fleet_vehicle_id });
    }
    if (query.assignee_employee_id) {
      qb.andWhere(
        't.id IN (SELECT scheduled_task_id FROM scheduled_task_assignments WHERE employee_id = :assigneeId)',
        { assigneeId: query.assignee_employee_id },
      );
    }

    qb.orderBy('t.scheduled_start_at', 'ASC').skip(skip).take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
    userId: string,
  ): Promise<ScheduledTask> {
    await this.ensureAccess(organizationId, userId);
    const task = await this.taskRepository.findOne({
      where: {
        id: taskId,
        organization_id: organizationId,
        task_type_code: taskTypeCode,
        deleted_at: IsNull(),
      },
      relations: [
        'assignments',
        'assignments.employee',
        'assignments.employee.user',
        'assignments.employee.providerRole',
        'department',
        'station',
        'room',
        'bed',
        'chair',
        'zone',
        'fleetVehicle',
        'labWorkstation',
        'shift',
        'statusHistory',
      ],
    });
    if (!task) throw new NotFoundException('Scheduled task not found');
    return task;
  }

  async create(
    organizationId: string,
    taskTypeCode: string,
    dto: CreateScheduledTaskBase,
    userId: string,
  ): Promise<ScheduledTask> {
    await this.ensureAccess(organizationId, userId);
    const type = await this.getTaskType(taskTypeCode);

    const start = new Date(dto.scheduled_start_at);
    const end = new Date(dto.scheduled_end_at);
    if (end < start) {
      throw new BadRequestException('scheduled_end_at must be >= scheduled_start_at');
    }

    await this.validateResourcesInOrg(organizationId, {
      department_id: dto.department_id,
      station_id: dto.station_id,
      room_id: dto.room_id,
      zone_id: dto.zone_id,
      fleet_vehicle_id: dto.fleet_vehicle_id,
      lab_workstation_id: dto.lab_workstation_id,
    });

    if (dto.primary_employee_id) {
      const emp = await this.employeeRepository.findOne({
        where: { id: dto.primary_employee_id, organization_id: organizationId },
      });
      if (!emp) {
        throw new BadRequestException('primary_employee_id does not belong to this organization');
      }
    }

    const initialStatus = (type.default_statuses?.initial as string) ?? 'scheduled';

    return this.dataSource.transaction(async (manager) => {
      const task = manager.create(ScheduledTask, {
        organization_id: organizationId,
        task_type_code: taskTypeCode,
        status: initialStatus,
        priority: dto.priority ?? 2,
        scheduled_start_at: start,
        scheduled_end_at: end,
        department_id: dto.department_id ?? null,
        station_id: dto.station_id ?? null,
        room_id: dto.room_id ?? null,
        bed_id: dto.bed_id ?? null,
        chair_id: dto.chair_id ?? null,
        zone_id: dto.zone_id ?? null,
        fleet_vehicle_id: dto.fleet_vehicle_id ?? null,
        lab_workstation_id: dto.lab_workstation_id ?? null,
        shift_id: dto.shift_id ?? null,
        subject_name: dto.subject_name ?? null,
        subject_phone: dto.subject_phone ?? null,
        subject_address: dto.subject_address ?? null,
        notes: dto.notes ?? null,
        details: (dto.details as Record<string, unknown>) ?? {},
        created_by: userId,
      });
      const saved = await manager.save(task);

      await manager.save(
        manager.create(ScheduledTaskStatusHistory, {
          scheduled_task_id: saved.id,
          from_status: null,
          to_status: initialStatus,
          changed_by: userId,
          reason: 'created',
        }),
      );

      if (dto.primary_employee_id) {
        await manager.save(
          manager.create(ScheduledTaskAssignment, {
            scheduled_task_id: saved.id,
            employee_id: dto.primary_employee_id,
            assignment_role: dto.primary_assignment_role ?? 'primary',
            is_primary: true,
          }),
        );
      }

      return this.findOneInTransaction(manager, organizationId, taskTypeCode, saved.id);
    });
  }

  private async findOneInTransaction(
    manager: import('typeorm').EntityManager,
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
  ): Promise<ScheduledTask> {
    const task = await manager.findOne(ScheduledTask, {
      where: {
        id: taskId,
        organization_id: organizationId,
        task_type_code: taskTypeCode,
        deleted_at: IsNull(),
      },
      relations: [
        'assignments',
        'assignments.employee',
        'assignments.employee.user',
        'assignments.employee.providerRole',
        'department',
        'station',
        'room',
        'zone',
        'fleetVehicle',
        'labWorkstation',
      ],
    });
    if (!task) throw new NotFoundException('Scheduled task not found after create');
    return task;
  }

  async update(
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
    dto: UpdateScheduledTaskBase,
    userId: string,
  ): Promise<ScheduledTask> {
    const task = await this.findOne(organizationId, taskTypeCode, taskId, userId);

    if (dto.scheduled_start_at !== undefined) task.scheduled_start_at = new Date(dto.scheduled_start_at);
    if (dto.scheduled_end_at !== undefined) task.scheduled_end_at = new Date(dto.scheduled_end_at);
    if (dto.actual_start_at !== undefined) task.actual_start_at = new Date(dto.actual_start_at);
    if (dto.actual_end_at !== undefined) task.actual_end_at = new Date(dto.actual_end_at);
    if (dto.priority !== undefined) task.priority = dto.priority;
    if (dto.department_id !== undefined) task.department_id = dto.department_id ?? null;
    if (dto.station_id !== undefined) task.station_id = dto.station_id ?? null;
    if (dto.room_id !== undefined) task.room_id = dto.room_id ?? null;
    if (dto.bed_id !== undefined) task.bed_id = dto.bed_id ?? null;
    if (dto.chair_id !== undefined) task.chair_id = dto.chair_id ?? null;
    if (dto.zone_id !== undefined) task.zone_id = dto.zone_id ?? null;
    if (dto.fleet_vehicle_id !== undefined) task.fleet_vehicle_id = dto.fleet_vehicle_id ?? null;
    if (dto.lab_workstation_id !== undefined) task.lab_workstation_id = dto.lab_workstation_id ?? null;
    if (dto.shift_id !== undefined) task.shift_id = dto.shift_id ?? null;
    if (dto.subject_name !== undefined) task.subject_name = dto.subject_name;
    if (dto.subject_phone !== undefined) task.subject_phone = dto.subject_phone;
    if (dto.subject_address !== undefined) task.subject_address = dto.subject_address;
    if (dto.notes !== undefined) task.notes = dto.notes;
    if (dto.details !== undefined) {
      task.details = { ...(task.details ?? {}), ...(dto.details as Record<string, unknown>) };
    }
    task.updated_by = userId;

    if (task.scheduled_end_at < task.scheduled_start_at) {
      throw new BadRequestException('scheduled_end_at must be >= scheduled_start_at');
    }

    await this.validateResourcesInOrg(organizationId, {
      department_id: task.department_id,
      station_id: task.station_id,
      room_id: task.room_id,
      zone_id: task.zone_id,
      fleet_vehicle_id: task.fleet_vehicle_id,
      lab_workstation_id: task.lab_workstation_id,
    });

    await this.taskRepository.save(task);
    return this.findOne(organizationId, taskTypeCode, taskId, userId);
  }

  async remove(
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
    userId: string,
  ): Promise<void> {
    const task = await this.findOne(organizationId, taskTypeCode, taskId, userId);
    task.deleted_at = new Date();
    task.updated_by = userId;
    await this.taskRepository.save(task);
  }

  async transitionStatus(
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
    dto: TransitionScheduledTaskStatusDto,
    userId: string,
  ): Promise<ScheduledTask> {
    const type = await this.getTaskType(taskTypeCode);
    this.validateStatusAgainstType(type, dto.to_status);

    return this.dataSource.transaction(async (manager) => {
      const task = await manager.findOne(ScheduledTask, {
        where: {
          id: taskId,
          organization_id: organizationId,
          task_type_code: taskTypeCode,
          deleted_at: IsNull(),
        },
      });
      if (!task) throw new NotFoundException('Scheduled task not found');

      const fromStatus = task.status;
      if (fromStatus === dto.to_status) {
        throw new ConflictException(`Task is already in status "${dto.to_status}"`);
      }

      task.status = dto.to_status;
      task.updated_by = userId;
      await manager.save(task);

      await manager.save(
        manager.create(ScheduledTaskStatusHistory, {
          scheduled_task_id: task.id,
          from_status: fromStatus,
          to_status: dto.to_status,
          changed_by: userId,
          reason: dto.reason ?? null,
        }),
      );

      return this.findOneInTransaction(manager, organizationId, taskTypeCode, task.id);
    });
  }

  async addAssignment(
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
    dto: CreateScheduledTaskAssignmentDto,
    userId: string,
  ): Promise<ScheduledTaskAssignment> {
    await this.findOne(organizationId, taskTypeCode, taskId, userId);

    const emp = await this.employeeRepository.findOne({
      where: { id: dto.employee_id, organization_id: organizationId },
    });
    if (!emp) throw new BadRequestException('Employee is not part of this organization');

    const existing = await this.assignmentRepository.findOne({
      where: {
        scheduled_task_id: taskId,
        employee_id: dto.employee_id,
        assignment_role: dto.assignment_role,
      },
    });
    if (existing) {
      throw new ConflictException('Assignment already exists for this employee and role');
    }

    const assignment = this.assignmentRepository.create({
      scheduled_task_id: taskId,
      employee_id: dto.employee_id,
      assignment_role: dto.assignment_role,
      employee_shift_id: dto.employee_shift_id ?? null,
      is_primary: dto.is_primary ?? false,
    });
    return this.assignmentRepository.save(assignment);
  }

  async removeAssignment(
    organizationId: string,
    taskTypeCode: string,
    taskId: string,
    assignmentId: string,
    userId: string,
  ): Promise<void> {
    await this.findOne(organizationId, taskTypeCode, taskId, userId);
    const assignment = await this.assignmentRepository.findOne({
      where: { id: assignmentId, scheduled_task_id: taskId },
    });
    if (!assignment) throw new NotFoundException('Assignment not found');
    await this.assignmentRepository.remove(assignment);
  }
}
