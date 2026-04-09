import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Department } from '../entities/department.entity';
import { Station } from '../entities/station.entity';
import { Room } from '../entities/room.entity';
import { Bed } from '../entities/bed.entity';
import { Chair } from '../entities/chair.entity';
import { Shift } from '../entities/shift.entity';
import { DepartmentShift } from '../entities/department-shift.entity';
import { ShiftRole } from '../entities/shift-role.entity';
import { DepartmentStaff } from '../entities/department-staff.entity';
import { Zone } from '../entities/zone.entity';
import { FleetVehicle } from '../entities/fleet-vehicle.entity';
import { LabWorkstation } from '../entities/lab-workstation.entity';
import { StationShiftAssignment } from '../entities/station-shift-assignment.entity';
import { RoomShiftAssignment } from '../entities/room-shift-assignment.entity';
import { ZoneShiftAssignment } from '../entities/zone-shift-assignment.entity';
import { VehicleShiftAssignment } from '../entities/vehicle-shift-assignment.entity';
import { WorkstationShiftAssignment } from '../entities/workstation-shift-assignment.entity';
import { ProviderRole } from '../../../employees/entities/provider-role.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateDepartmentDto, InlineShiftDto } from '../dto/create-department.dto';
import { UpdateDepartmentDto } from '../dto/update-department.dto';
import { QueryDepartmentDto } from '../dto/query-department.dto';

/** Map frontend recurrence strings to backend recurrence_type values. */
const RECURRENCE_MAP: Record<string, string> = {
  'full-week': 'FULL_WEEK',
  weekdays: 'WEEKDAYS',
  weekend: 'WEEKENDS',
  custom: 'CUSTOM',
};

/** Map frontend day names to day numbers (1=Mon … 7=Sun). */
const DAY_MAP: Record<string, number> = {
  mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6, sun: 7,
};

@Injectable()
export class DepartmentService {
  constructor(
    @InjectRepository(Department)
    private readonly departmentRepository: Repository<Department>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    @InjectRepository(Station)
    private readonly stationRepository: Repository<Station>,
    @InjectRepository(Room)
    private readonly roomRepository: Repository<Room>,
    @InjectRepository(Bed)
    private readonly bedRepository: Repository<Bed>,
    @InjectRepository(Chair)
    private readonly chairRepository: Repository<Chair>,
    @InjectRepository(Shift)
    private readonly shiftRepository: Repository<Shift>,
    @InjectRepository(DepartmentShift)
    private readonly departmentShiftRepository: Repository<DepartmentShift>,
    @InjectRepository(ShiftRole)
    private readonly shiftRoleRepository: Repository<ShiftRole>,
    @InjectRepository(DepartmentStaff)
    private readonly departmentStaffRepository: Repository<DepartmentStaff>,
    @InjectRepository(Zone)
    private readonly zoneRepository: Repository<Zone>,
    @InjectRepository(FleetVehicle)
    private readonly fleetVehicleRepository: Repository<FleetVehicle>,
    @InjectRepository(LabWorkstation)
    private readonly labWorkstationRepository: Repository<LabWorkstation>,
    @InjectRepository(StationShiftAssignment)
    private readonly stationShiftAsgnRepository: Repository<StationShiftAssignment>,
    @InjectRepository(RoomShiftAssignment)
    private readonly roomShiftAsgnRepository: Repository<RoomShiftAssignment>,
    @InjectRepository(ZoneShiftAssignment)
    private readonly zoneShiftAsgnRepository: Repository<ZoneShiftAssignment>,
    @InjectRepository(VehicleShiftAssignment)
    private readonly vehicleShiftAsgnRepository: Repository<VehicleShiftAssignment>,
    @InjectRepository(WorkstationShiftAssignment)
    private readonly workstationShiftAsgnRepository: Repository<WorkstationShiftAssignment>,
    @InjectRepository(ProviderRole)
    private readonly providerRoleRepository: Repository<ProviderRole>,
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

  // ── LIST ────────────────────────────────────────────────────────────

  async findAll(
    organizationId: string,
    query: QueryDepartmentDto,
    userId: string,
  ): Promise<{ data: Department[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    const { page = 1, limit = 20, is_active } = query;
    const skip = (page - 1) * limit;

    // First get paginated department IDs
    const idQb = this.departmentRepository
      .createQueryBuilder('d')
      .select('d.id')
      .where('d.organization_id = :organizationId', { organizationId });

    if (is_active !== undefined) {
      idQb.andWhere('d.is_active = :is_active', { is_active });
    }
    idQb.orderBy('d.sort_order', 'ASC', 'NULLS LAST').addOrderBy('d.name', 'ASC');

    const total = await idQb.getCount();
    const idRows = await idQb.skip(skip).take(limit).getMany();
    const ids = idRows.map((r) => r.id);

    if (ids.length === 0) return { data: [], total, page, limit };

    // Then load full data with all relations for those IDs
    const data = await this.departmentRepository.find({
      where: ids.map((id) => ({ id, organization_id: organizationId })),
      relations: [
        'stations',
        'stations.rooms',
        'stations.rooms.beds',
        'stations.rooms.chairs',
        'zones',
        'zones.shiftAssignments',
        'fleetVehicles',
        'fleetVehicles.shiftAssignments',
        'labWorkstations',
        'labWorkstations.shiftAssignments',
        'departmentShifts',
        'departmentShifts.shift',
        'departmentShifts.shift.shiftRoles',
        'departmentShifts.shift.shiftRoles.providerRole',
        'departmentStaff',
      ],
      order: { sort_order: 'ASC', name: 'ASC' },
    });

    return { data, total, page, limit };
  }

  // ── DETAIL ──────────────────────────────────────────────────────────

  async findOne(organizationId: string, departmentId: string, userId: string): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
      relations: [
        'stations',
        'stations.rooms',
        'stations.rooms.beds',
        'stations.rooms.chairs',
        'stations.rooms.shiftAssignments',
        'zones',
        'zones.shiftAssignments',
        'fleetVehicles',
        'fleetVehicles.shiftAssignments',
        'labWorkstations',
        'labWorkstations.shiftAssignments',
        'departmentShifts',
        'departmentShifts.shift',
        'departmentShifts.shift.shiftRoles',
        'departmentShifts.shift.shiftRoles.providerRole',
        'departmentStaff',
      ],
    });
    if (!department) throw new NotFoundException('Department not found');
    return department;
  }

  // ── CREATE (transactional) ──────────────────────────────────────────

  async create(
    organizationId: string,
    dto: CreateDepartmentDto,
    userId: string,
  ): Promise<Department> {
    await this.ensureAccess(organizationId, userId);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // 1. Create department
      const department = queryRunner.manager.create(Department, {
        organization_id: organizationId,
        name: dto.name,
        code: dto.code ?? null,
        description: dto.description ?? null,
        department_type: dto.department_type ?? null,
        layout_type: dto.layout_type ?? null,
        department_head: dto.department_head ?? null,
        allow_multi_station_coverage: dto.allow_multi_station_coverage ?? false,
        is_active: dto.is_active ?? true,
        sort_order: dto.sort_order ?? null,
      });
      const saved = await queryRunner.manager.save(Department, department);

      // 2. Create shifts + shift roles + department_shifts junction
      const tempIdToRealId = new Map<string, string>();
      if (dto.available_shifts?.length) {
        for (const s of dto.available_shifts) {
          const shift = await this.createShiftFromInline(
            queryRunner.manager,
            organizationId,
            s,
          );
          tempIdToRealId.set(s.temp_id, shift.id);
          // Link shift to department
          await queryRunner.manager.save(DepartmentShift, queryRunner.manager.create(DepartmentShift, {
            department_id: saved.id,
            shift_id: shift.id,
          }));
        }
      }

      // Helper to remap temp shift IDs to real IDs
      const remapIds = (ids?: string[]): string[] | undefined => {
        if (!ids?.length) return undefined;
        return ids
          .map((id) => tempIdToRealId.get(id) ?? id)
          .filter(Boolean);
      };

      const remapRecord = <T>(rec?: Record<string, T>): Record<string, T> | undefined => {
        if (!rec) return undefined;
        const result: Record<string, T> = {};
        for (const [key, val] of Object.entries(rec)) {
          result[tempIdToRealId.get(key) ?? key] = val;
        }
        return result;
      };

      // 3. Create department staff
      if (dto.staff?.length) {
        for (let i = 0; i < dto.staff.length; i++) {
          const s = dto.staff[i];
          await queryRunner.manager.save(DepartmentStaff, queryRunner.manager.create(DepartmentStaff, {
            department_id: saved.id,
            staff_type: s.type,
            staff_name: s.name,
            quantity: s.quantity ?? 1,
            assignment_level: s.assignment_level ?? null,
            assignment_type: s.assignment_type ?? null,
            shift_ids: remapIds(s.shift_ids) ?? null,
            staff_by_shift: remapRecord(s.staff_by_shift) ?? null,
            staff_min_max_by_shift: remapRecord(s.staff_min_max_by_shift) ?? null,
            sort_order: i,
          }));
        }
      }

      // 4. Create stations (for 'stations' layout)
      if (dto.stations?.length) {
        for (let si = 0; si < dto.stations.length; si++) {
          const s = dto.stations[si];
          const station = await queryRunner.manager.save(Station, queryRunner.manager.create(Station, {
            department_id: saved.id,
            name: s.name,
            location: s.location ?? null,
            multi_station_am: s.multi_station_am ?? false,
            multi_station_pm: s.multi_station_pm ?? false,
            multi_station_noc: s.multi_station_noc ?? false,
            custom_shift_times: s.custom_shift_times ?? null,
            configuration_type: s.configuration_type ?? null,
            default_beds_per_room: s.default_beds_per_room ?? null,
            default_chairs_per_room: s.default_chairs_per_room ?? null,
            is_active: true,
            sort_order: si,
          }));
          // Station shift assignments
          const stationShiftIds = remapIds(s.shift_ids);
          if (stationShiftIds?.length) {
            for (const shiftId of stationShiftIds) {
              await queryRunner.manager.save(StationShiftAssignment, queryRunner.manager.create(StationShiftAssignment, {
                station_id: station.id,
                shift_id: shiftId,
              }));
            }
          }
          // Station rooms
          if (s.rooms?.length) {
            const configType = s.configuration_type ?? 'BEDS';
            for (let ri = 0; ri < s.rooms.length; ri++) {
              const r = s.rooms[ri];
              const bedsCount = configType === 'BEDS' ? (r.beds ?? s.default_beds_per_room ?? 0) : 0;
              const chairsCount = configType === 'CHAIRS' ? (r.chairs ?? s.default_chairs_per_room ?? 0) : 0;
              const room = await queryRunner.manager.save(Room, queryRunner.manager.create(Room, {
                station_id: station.id,
                department_id: saved.id,
                name: r.name,
                configuration_type: configType,
                beds_per_room: bedsCount || null,
                chairs_per_room: chairsCount || null,
                is_active: true,
                sort_order: ri,
              }));
              for (let b = 0; b < bedsCount; b++) {
                await queryRunner.manager.save(Bed, queryRunner.manager.create(Bed, {
                  room_id: room.id,
                  bed_number: String(b + 1),
                }));
              }
              for (let c = 0; c < chairsCount; c++) {
                await queryRunner.manager.save(Chair, queryRunner.manager.create(Chair, {
                  room_id: room.id,
                  chair_number: String(c + 1),
                }));
              }
            }
          }
        }
      }

      // 5. Create rooms (for 'rooms' layout — creates a default station)
      if (dto.rooms?.length) {
        const defaultStation = await queryRunner.manager.save(Station, queryRunner.manager.create(Station, {
          department_id: saved.id,
          name: `${dto.name} - Default`,
          is_active: true,
          sort_order: 0,
        }));
        for (let ri = 0; ri < dto.rooms.length; ri++) {
          const r = dto.rooms[ri];
          const bedsCount = r.beds ?? 0;
          const chairsCount = r.chairs ?? 0;
          const room = await queryRunner.manager.save(Room, queryRunner.manager.create(Room, {
            station_id: defaultStation.id,
            department_id: saved.id,
            name: r.name,
            room_type: r.room_type ?? null,
            floor: r.floor ?? null,
            location_or_wing: r.wing ?? null,
            configuration_type: bedsCount > 0 ? 'BEDS' : chairsCount > 0 ? 'CHAIRS' : null,
            beds_per_room: bedsCount || null,
            chairs_per_room: chairsCount || null,
            is_active: true,
            sort_order: ri,
          }));
          // Room shift assignments
          const roomShiftIds = remapIds(r.shift_ids);
          if (roomShiftIds?.length) {
            for (const shiftId of roomShiftIds) {
              await queryRunner.manager.save(RoomShiftAssignment, queryRunner.manager.create(RoomShiftAssignment, {
                room_id: room.id,
                shift_id: shiftId,
              }));
            }
          }
          for (let b = 0; b < bedsCount; b++) {
            await queryRunner.manager.save(Bed, queryRunner.manager.create(Bed, {
              room_id: room.id,
              bed_number: String(b + 1),
            }));
          }
          for (let c = 0; c < chairsCount; c++) {
            await queryRunner.manager.save(Chair, queryRunner.manager.create(Chair, {
              room_id: room.id,
              chair_number: String(c + 1),
            }));
          }
        }
      }

      // 6. Create zones (for 'field' layout)
      if (dto.field_zones?.length) {
        for (let i = 0; i < dto.field_zones.length; i++) {
          const z = dto.field_zones[i];
          const zone = await queryRunner.manager.save(Zone, queryRunner.manager.create(Zone, {
            department_id: saved.id,
            name: z.name,
            area: z.area ?? null,
            patient_count: z.patient_count ?? 0,
            is_active: true,
            sort_order: i,
          }));
          const zoneShiftIds = remapIds(z.shift_ids);
          if (zoneShiftIds?.length) {
            for (const shiftId of zoneShiftIds) {
              await queryRunner.manager.save(ZoneShiftAssignment, queryRunner.manager.create(ZoneShiftAssignment, {
                zone_id: zone.id,
                shift_id: shiftId,
              }));
            }
          }
        }
      }

      // 7. Create fleet vehicles (for 'fleet' layout)
      if (dto.fleet_vehicles?.length) {
        for (let i = 0; i < dto.fleet_vehicles.length; i++) {
          const v = dto.fleet_vehicles[i];
          const vehicle = await queryRunner.manager.save(FleetVehicle, queryRunner.manager.create(FleetVehicle, {
            department_id: saved.id,
            name: v.name,
            vehicle_id: v.vehicle_id ?? null,
            vehicle_type: v.vehicle_type ?? null,
            capacity: v.capacity ?? 0,
            is_active: true,
            sort_order: i,
          }));
          const vehicleShiftIds = remapIds(v.shift_ids);
          if (vehicleShiftIds?.length) {
            for (const shiftId of vehicleShiftIds) {
              await queryRunner.manager.save(VehicleShiftAssignment, queryRunner.manager.create(VehicleShiftAssignment, {
                vehicle_id: vehicle.id,
                shift_id: shiftId,
              }));
            }
          }
        }
      }

      // 8. Create lab workstations (for 'lab' layout)
      if (dto.lab_workstations?.length) {
        for (let i = 0; i < dto.lab_workstations.length; i++) {
          const w = dto.lab_workstations[i];
          const ws = await queryRunner.manager.save(LabWorkstation, queryRunner.manager.create(LabWorkstation, {
            department_id: saved.id,
            name: w.name,
            equipment: w.equipment ?? null,
            workstation_type: w.workstation_type ?? null,
            is_active: true,
            sort_order: i,
          }));
          const wsShiftIds = remapIds(w.shift_ids);
          if (wsShiftIds?.length) {
            for (const shiftId of wsShiftIds) {
              await queryRunner.manager.save(WorkstationShiftAssignment, queryRunner.manager.create(WorkstationShiftAssignment, {
                workstation_id: ws.id,
                shift_id: shiftId,
              }));
            }
          }
        }
      }

      await queryRunner.commitTransaction();
      // Return the full department with all nested relations
      return this.findOne(organizationId, saved.id, userId);
    } catch (err) {
      await queryRunner.rollbackTransaction();
      throw err;
    } finally {
      await queryRunner.release();
    }
  }

  // ── UPDATE ──────────────────────────────────────────────────────────

  async update(
    organizationId: string,
    departmentId: string,
    dto: UpdateDepartmentDto,
    userId: string,
  ): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.findOne(organizationId, departmentId, userId);
    if (dto.name !== undefined) department.name = dto.name;
    if (dto.code !== undefined) department.code = dto.code;
    if (dto.description !== undefined) department.description = dto.description;
    if (dto.department_type !== undefined) department.department_type = dto.department_type;
    if (dto.layout_type !== undefined) department.layout_type = dto.layout_type;
    if (dto.department_head !== undefined) department.department_head = dto.department_head;
    if (dto.allow_multi_station_coverage !== undefined) department.allow_multi_station_coverage = dto.allow_multi_station_coverage;
    if (dto.is_active !== undefined) department.is_active = dto.is_active;
    if (dto.sort_order !== undefined) department.sort_order = dto.sort_order;
    return this.departmentRepository.save(department);
  }

  // ── DELETE ──────────────────────────────────────────────────────────

  async remove(organizationId: string, departmentId: string, userId: string): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.departmentRepository.findOne({
      where: { id: departmentId, organization_id: organizationId },
    });
    if (!department) throw new NotFoundException('Department not found');
    await this.departmentRepository.remove(department);
  }

  // ── PRIVATE HELPERS ─────────────────────────────────────────────────

  /**
   * Create a Shift entity from an inline shift DTO (used during department creation).
   * Converts HH:mm time strings to timestamps using a base date.
   */
  private async createShiftFromInline(
    manager: typeof this.dataSource.manager,
    organizationId: string,
    s: InlineShiftDto,
  ): Promise<Shift> {
    // Convert HH:mm to Date using a base date
    const baseDate = '1970-01-01';
    const startAt = new Date(`${baseDate}T${s.start_time}:00Z`);
    const endAt = new Date(`${baseDate}T${s.end_time}:00Z`);

    // Map recurrence
    const recurrenceType = s.recurrence ? (RECURRENCE_MAP[s.recurrence] ?? 'ONE_TIME') : 'ONE_TIME';

    // Map custom days to day numbers
    let recurrenceDays: string | null = null;
    if (s.custom_days?.length) {
      recurrenceDays = s.custom_days
        .map((d) => DAY_MAP[d.toLowerCase()])
        .filter(Boolean)
        .join(',');
    }

    // Duration dates
    let recurrenceStartDate: Date | null = null;
    let recurrenceEndDate: Date | null = null;
    if (s.duration === 'date-range') {
      if (s.duration_start_date) recurrenceStartDate = new Date(s.duration_start_date);
      if (s.duration_end_date) recurrenceEndDate = new Date(s.duration_end_date);
    }

    const shift = await manager.save(Shift, manager.create(Shift, {
      organization_id: organizationId,
      name: s.name,
      start_at: startAt,
      end_at: endAt,
      shift_type: null,
      status: 'ACTIVE',
      recurrence_type: recurrenceType,
      recurrence_days: recurrenceDays,
      recurrence_start_date: recurrenceStartDate,
      recurrence_end_date: recurrenceEndDate,
    }));

    // Create shift role assignments
    if (s.assigned_roles?.length) {
      for (const roleCode of s.assigned_roles) {
        const role = await this.providerRoleRepository.findOne({ where: { code: roleCode } });
        if (role) {
          await manager.save(ShiftRole, manager.create(ShiftRole, {
            shift_id: shift.id,
            provider_role_id: role.id,
          }));
        }
      }
    }

    return shift;
  }
}
