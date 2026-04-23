import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
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
import { EmployeeShift } from '../entities/employee-shift.entity';
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
// localToUtc / FALLBACK_TIMEZONE no longer needed — shift times are stored as-is

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
  private readonly logger = new Logger('DepartmentService'); // DEBUG

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
    @InjectRepository(EmployeeShift)
    private readonly employeeShiftRepository: Repository<EmployeeShift>,
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
    const { page = 1, limit = 20, is_active, search, department_type, layout_type } = query;
    const skip = (page - 1) * limit;

    // First get paginated department IDs
    const idQb = this.departmentRepository
      .createQueryBuilder('d')
      .select('d.id')
      .where('d.organization_id = :organizationId', { organizationId });

    if (is_active !== undefined) {
      idQb.andWhere('d.is_active = :is_active', { is_active });
    }
    if (search?.trim()) {
      idQb.andWhere(
        '(LOWER(d.name) LIKE :search OR LOWER(d.code) LIKE :search OR LOWER(d.description) LIKE :search)',
        { search: `%${search.trim().toLowerCase()}%` },
      );
    }
    if (department_type) {
      idQb.andWhere('d.department_type = :department_type', { department_type });
    }
    if (layout_type) {
      idQb.andWhere('d.layout_type = :layout_type', { layout_type });
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
        'departmentStaff.providerRole',
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
        'departmentStaff.providerRole',
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
            dto.timezone,
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
            provider_role_id: s.provider_role_id ?? null,
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

  // ── UPDATE (transactional) ──────────────────────────────────────────

  async update(
    organizationId: string,
    departmentId: string,
    dto: UpdateDepartmentDto,
    userId: string,
  ): Promise<Department> {
    await this.ensureAccess(organizationId, userId);
    const department = await this.findOne(organizationId, departmentId, userId);

    const hasNestedData =
      dto.available_shifts !== undefined ||
      dto.staff !== undefined ||
      dto.stations !== undefined ||
      dto.rooms !== undefined ||
      dto.field_zones !== undefined ||
      dto.fleet_vehicles !== undefined ||
      dto.lab_workstations !== undefined;

    // DEBUG: Log which nested arrays were detected
    this.logger.debug(`[UPDATE] dept=${departmentId} hasNestedData=${hasNestedData}`);
    this.logger.debug(`[UPDATE] nested flags — stations:${dto.stations !== undefined} rooms:${dto.rooms !== undefined} shifts:${dto.available_shifts !== undefined} staff:${dto.staff !== undefined} zones:${dto.field_zones !== undefined} vehicles:${dto.fleet_vehicles !== undefined} workstations:${dto.lab_workstations !== undefined}`);

    // Simple metadata-only update — no transaction needed
    if (!hasNestedData) {
      this.logger.debug(`[UPDATE] metadata-only path (no nested data)`); // DEBUG
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

    // Full transactional update with nested entities
    this.logger.debug(`[UPDATE] entering transactional path`); // DEBUG
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // 1. Update department metadata
      if (dto.name !== undefined) department.name = dto.name;
      if (dto.code !== undefined) department.code = dto.code;
      if (dto.description !== undefined) department.description = dto.description;
      if (dto.department_type !== undefined) department.department_type = dto.department_type;
      if (dto.layout_type !== undefined) department.layout_type = dto.layout_type;
      if (dto.department_head !== undefined) department.department_head = dto.department_head;
      if (dto.allow_multi_station_coverage !== undefined) department.allow_multi_station_coverage = dto.allow_multi_station_coverage;
      if (dto.is_active !== undefined) department.is_active = dto.is_active;
      if (dto.sort_order !== undefined) department.sort_order = dto.sort_order;
      await queryRunner.manager.save(Department, department);

      // 2. Merge shifts — id-based diff, no wipe-and-recreate.
      //
      // Why the old behavior was wrong: it ran `delete(Shift, shiftId)` for
      // every department shift on every PATCH that carried `available_shifts`,
      // which cascaded to employee_shifts and station_shift_assignments. Every
      // save of this form destroyed historical assignments and re-created
      // Shift records with fresh UUIDs, breaking any external reference
      // (including the MCP tool's cached IDs).
      //
      // New behavior:
      //   - Incoming entry with `id` that matches an existing link → UPDATE
      //     in place. Preserves shift_id, so employee_shifts and station
      //     links survive untouched.
      //   - Incoming entry with no `id` → CREATE new, link it.
      //   - Existing link not present in the incoming set → DELETE, but
      //     only after confirming no employee_shifts rows reference it.
      //     Otherwise throw BadRequestException so data loss can't happen
      //     silently from the UI.
      const tempIdToRealId = new Map<string, string>();
      if (dto.available_shifts !== undefined) {
        this.logger.debug(
          `[UPDATE] merging shifts — ${dto.available_shifts.length} incoming entries`,
        );

        const existingLinks = await queryRunner.manager.find(DepartmentShift, {
          where: { department_id: departmentId },
        });
        const existingShiftIds = new Set(existingLinks.map((l) => l.shift_id));

        // Partition incoming entries.
        const incomingWithId = dto.available_shifts.filter((s) => !!s.id);
        const incomingWithoutId = dto.available_shifts.filter((s) => !s.id);

        // Validate: every `id` provided must point at a shift currently
        // linked to this department. Reject stale IDs loudly rather than
        // silently creating/duplicating records.
        for (const s of incomingWithId) {
          if (!existingShiftIds.has(s.id!)) {
            throw new BadRequestException(
              `available_shifts[].id="${s.id}" is not linked to this department. ` +
                `Omit id to create a new shift.`,
            );
          }
        }

        // Figure out which existing shifts are being removed.
        const incomingIds = new Set(incomingWithId.map((s) => s.id!));
        const removedShiftIds = [...existingShiftIds].filter(
          (id) => !incomingIds.has(id),
        );

        // Guard: refuse to drop a shift that still has employee_shifts rows.
        // This is the last line of defense against accidental data loss
        // from a stale or partial form submission.
        if (removedShiftIds.length > 0) {
          const assignmentCounts = await queryRunner.manager
            .createQueryBuilder(EmployeeShift, 'es')
            .select('es.shift_id', 'shift_id')
            .addSelect('COUNT(*)', 'count')
            .where('es.shift_id IN (:...ids)', { ids: removedShiftIds })
            .groupBy('es.shift_id')
            .getRawMany<{ shift_id: string; count: string }>();
          const blocking = assignmentCounts.filter(
            (r) => Number(r.count) > 0,
          );
          if (blocking.length > 0) {
            const shifts = await queryRunner.manager.find(Shift, {
              where: blocking.map((b) => ({ id: b.shift_id })),
              select: ['id', 'name'],
            });
            const nameById = new Map(shifts.map((sh) => [sh.id, sh.name]));
            const details = blocking
              .map(
                (b) =>
                  `${nameById.get(b.shift_id) ?? b.shift_id} (${b.count} assignment${b.count === '1' ? '' : 's'})`,
              )
              .join(', ');
            throw new BadRequestException(
              `Cannot remove shifts with existing employee assignments: ${details}. ` +
                `Cancel or reassign those employee_shifts first.`,
            );
          }
        }

        // Safe to remove — no assignments reference the shifts being dropped.
        for (const shiftId of removedShiftIds) {
          const link = existingLinks.find((l) => l.shift_id === shiftId);
          if (link) await queryRunner.manager.remove(DepartmentShift, link);
          // Delete the shift only if no other department links to it.
          const otherLink = await queryRunner.manager.findOne(DepartmentShift, {
            where: { shift_id: shiftId },
          });
          if (!otherLink) {
            await queryRunner.manager.delete(Shift, shiftId);
          }
        }

        // Update existing shifts in place.
        for (const s of incomingWithId) {
          const shift = await queryRunner.manager.findOne(Shift, {
            where: { id: s.id! },
          });
          if (!shift) {
            // Should not happen given the earlier validation, but guard for
            // the race where a concurrent writer deleted the row.
            throw new BadRequestException(
              `Shift ${s.id} disappeared mid-update; retry.`,
            );
          }
          await this.applyShiftInlineFields(queryRunner.manager, shift, s);
          tempIdToRealId.set(s.temp_id, shift.id);
        }

        // Create genuinely new shifts and link them.
        for (const s of incomingWithoutId) {
          const shift = await this.createShiftFromInline(
            queryRunner.manager,
            organizationId,
            s,
            dto.timezone,
          );
          tempIdToRealId.set(s.temp_id, shift.id);
          await queryRunner.manager.save(
            DepartmentShift,
            queryRunner.manager.create(DepartmentShift, {
              department_id: departmentId,
              shift_id: shift.id,
            }),
          );
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

      // 3. Replace staff
      if (dto.staff !== undefined) {
        this.logger.debug(`[UPDATE] replacing staff — ${dto.staff.length} entries`); // DEBUG
        await queryRunner.manager.delete(DepartmentStaff, { department_id: departmentId });
        for (let i = 0; i < dto.staff.length; i++) {
          const s = dto.staff[i];
          await queryRunner.manager.save(DepartmentStaff, queryRunner.manager.create(DepartmentStaff, {
            department_id: departmentId,
            provider_role_id: s.provider_role_id ?? null,
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

      // 4. Merge stations (for 'stations' layout) — id-based, same contract
      // as shifts above. Stations with `id` are preserved in place so the
      // station_id stays stable for every employee_shifts row that points
      // at them. Stations without `id` are created fresh. Removed stations
      // are deleted only after confirming no employee_shifts rows reference
      // them — otherwise throw BadRequestException.
      if (dto.stations !== undefined) {
        this.logger.debug(
          `[UPDATE] merging stations — ${dto.stations.length} incoming entries`,
        );

        const existingStations = await queryRunner.manager.find(Station, {
          where: { department_id: departmentId },
        });
        const existingStationIds = new Set(existingStations.map((st) => st.id));

        // Validate incoming ids map to real rows on this department.
        for (const s of dto.stations) {
          if (s.id && !existingStationIds.has(s.id)) {
            throw new BadRequestException(
              `stations[].id="${s.id}" is not a station on this department. ` +
                `Omit id to create a new station.`,
            );
          }
        }

        // Work out which existing stations are being removed.
        const incomingIds = new Set(
          dto.stations.filter((s) => s.id).map((s) => s.id!),
        );
        const removedStationIds = [...existingStationIds].filter(
          (id) => !incomingIds.has(id),
        );

        // Guard: refuse to drop a station that still has employee_shifts.
        if (removedStationIds.length > 0) {
          const blockingCount = await queryRunner.manager
            .createQueryBuilder(EmployeeShift, 'es')
            .where('es.station_id IN (:...ids)', { ids: removedStationIds })
            .getCount();
          if (blockingCount > 0) {
            const blockingStations = existingStations
              .filter((st) => removedStationIds.includes(st.id))
              .map((st) => st.name)
              .join(', ');
            throw new BadRequestException(
              `Cannot remove stations with existing employee assignments ` +
                `(${blockingCount} assignment row${blockingCount === 1 ? '' : 's'} ` +
                `on: ${blockingStations}). Reassign or cancel those first.`,
            );
          }
          // Safe — CASCADE will take care of rooms/beds/chairs/links.
          await queryRunner.manager.delete(Station, removedStationIds);
        }

        // Upsert the incoming stations in order.
        for (let si = 0; si < dto.stations.length; si++) {
          const s = dto.stations[si];
          let station: Station;
          if (s.id) {
            // UPDATE existing in place.
            station = existingStations.find((st) => st.id === s.id)!;
            station.name = s.name;
            station.location = s.location ?? null;
            station.multi_station_am = s.multi_station_am ?? false;
            station.multi_station_pm = s.multi_station_pm ?? false;
            station.multi_station_noc = s.multi_station_noc ?? false;
            station.custom_shift_times = s.custom_shift_times ?? null;
            station.configuration_type = s.configuration_type ?? null;
            station.default_beds_per_room = s.default_beds_per_room ?? null;
            station.default_chairs_per_room = s.default_chairs_per_room ?? null;
            station.is_active = true;
            station.sort_order = si;
            station = await queryRunner.manager.save(Station, station);
          } else {
            station = await queryRunner.manager.save(
              Station,
              queryRunner.manager.create(Station, {
                department_id: departmentId,
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
              }),
            );
          }

          // Replace station_shift_assignments for this station. These are
          // pure join rows — no FKs point at them from employee_shifts —
          // so a delete-and-recreate is safe and simpler than diffing.
          await queryRunner.manager.delete(StationShiftAssignment, {
            station_id: station.id,
          });
          const stationShiftIds = remapIds(s.shift_ids);
          if (stationShiftIds?.length) {
            for (const shiftId of stationShiftIds) {
              await queryRunner.manager.save(
                StationShiftAssignment,
                queryRunner.manager.create(StationShiftAssignment, {
                  station_id: station.id,
                  shift_id: shiftId,
                }),
              );
            }
          }

          // Rooms: if the caller sent a rooms array we rebuild them. Guard
          // against clobbering rooms that have live employee_shifts rows
          // pointing at them (or at their beds/chairs). For now we require
          // the caller to handle room-level merges explicitly by passing
          // room `id`s once that DTO is expanded; until then, refuse to
          // wipe rooms with assignment history.
          if (s.rooms !== undefined) {
            const existingRoomIds = (
              await queryRunner.manager.find(Room, {
                where: { station_id: station.id },
                select: ['id'],
              })
            ).map((r) => r.id);
            if (existingRoomIds.length > 0) {
              const roomAssignmentCount = await queryRunner.manager
                .createQueryBuilder(EmployeeShift, 'es')
                .where(
                  'es.room_id IN (:...ids) OR es.bed_id IN (SELECT id FROM beds WHERE room_id IN (:...ids)) OR es.chair_id IN (SELECT id FROM chairs WHERE room_id IN (:...ids))',
                  { ids: existingRoomIds },
                )
                .getCount();
              if (roomAssignmentCount > 0) {
                throw new BadRequestException(
                  `Cannot rebuild rooms on station "${station.name}" — ` +
                    `${roomAssignmentCount} employee assignment row${roomAssignmentCount === 1 ? '' : 's'} ` +
                    `reference a room/bed/chair here. Cancel those first.`,
                );
              }
              await queryRunner.manager.delete(Room, { station_id: station.id });
            }

            const configType = s.configuration_type ?? 'BEDS';
            for (let ri = 0; ri < s.rooms.length; ri++) {
              const r = s.rooms[ri];
              const bedsCount =
                configType === 'BEDS'
                  ? (r.beds ?? s.default_beds_per_room ?? 0)
                  : 0;
              const chairsCount =
                configType === 'CHAIRS'
                  ? (r.chairs ?? s.default_chairs_per_room ?? 0)
                  : 0;
              const room = await queryRunner.manager.save(
                Room,
                queryRunner.manager.create(Room, {
                  station_id: station.id,
                  department_id: departmentId,
                  name: r.name,
                  configuration_type: configType,
                  beds_per_room: bedsCount || null,
                  chairs_per_room: chairsCount || null,
                  is_active: true,
                  sort_order: ri,
                }),
              );
              for (let b = 0; b < bedsCount; b++) {
                await queryRunner.manager.save(
                  Bed,
                  queryRunner.manager.create(Bed, {
                    room_id: room.id,
                    bed_number: String(b + 1),
                  }),
                );
              }
              for (let c = 0; c < chairsCount; c++) {
                await queryRunner.manager.save(
                  Chair,
                  queryRunner.manager.create(Chair, {
                    room_id: room.id,
                    chair_number: String(c + 1),
                  }),
                );
              }
            }
          }
        }
      }

      // 5. Replace rooms (for 'rooms' layout — creates a default station)
      if (dto.rooms !== undefined) {
        this.logger.debug(`[UPDATE] replacing rooms — ${dto.rooms.length} rooms to create`); // DEBUG
        // CASCADE deletes rooms, beds, chairs under existing stations
        await queryRunner.manager.delete(Station, { department_id: departmentId });
        const deptName = dto.name ?? department.name;
        const defaultStation = await queryRunner.manager.save(Station, queryRunner.manager.create(Station, {
          department_id: departmentId,
          name: `${deptName} - Default`,
          is_active: true,
          sort_order: 0,
        }));
        for (let ri = 0; ri < dto.rooms.length; ri++) {
          const r = dto.rooms[ri];
          const bedsCount = r.beds ?? 0;
          const chairsCount = r.chairs ?? 0;
          const room = await queryRunner.manager.save(Room, queryRunner.manager.create(Room, {
            station_id: defaultStation.id,
            department_id: departmentId,
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

      // 6. Replace zones (for 'field' layout)
      if (dto.field_zones !== undefined) {
        this.logger.debug(`[UPDATE] replacing zones — ${dto.field_zones.length} zones to create`); // DEBUG
        await queryRunner.manager.delete(Zone, { department_id: departmentId });
        for (let i = 0; i < dto.field_zones.length; i++) {
          const z = dto.field_zones[i];
          const zone = await queryRunner.manager.save(Zone, queryRunner.manager.create(Zone, {
            department_id: departmentId,
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

      // 7. Replace fleet vehicles (for 'fleet' layout)
      if (dto.fleet_vehicles !== undefined) {
        this.logger.debug(`[UPDATE] replacing fleet vehicles — ${dto.fleet_vehicles.length} vehicles to create`); // DEBUG
        await queryRunner.manager.delete(FleetVehicle, { department_id: departmentId });
        for (let i = 0; i < dto.fleet_vehicles.length; i++) {
          const v = dto.fleet_vehicles[i];
          const vehicle = await queryRunner.manager.save(FleetVehicle, queryRunner.manager.create(FleetVehicle, {
            department_id: departmentId,
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

      // 8. Replace lab workstations (for 'lab' layout)
      if (dto.lab_workstations !== undefined) {
        this.logger.debug(`[UPDATE] replacing lab workstations — ${dto.lab_workstations.length} workstations to create`); // DEBUG
        await queryRunner.manager.delete(LabWorkstation, { department_id: departmentId });
        for (let i = 0; i < dto.lab_workstations.length; i++) {
          const w = dto.lab_workstations[i];
          const ws = await queryRunner.manager.save(LabWorkstation, queryRunner.manager.create(LabWorkstation, {
            department_id: departmentId,
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
      this.logger.debug(`[UPDATE] transaction committed successfully for dept=${departmentId}`); // DEBUG
      const result = await this.findOne(organizationId, departmentId, userId);
      this.logger.debug(`[UPDATE] returning dept with stations=${result.stations?.length ?? 0} zones=${result.zones?.length ?? 0} vehicles=${result.fleetVehicles?.length ?? 0} workstations=${result.labWorkstations?.length ?? 0}`); // DEBUG
      return result;
    } catch (err) {
      this.logger.error(`[UPDATE] transaction FAILED for dept=${departmentId}: ${err.message}`, err.stack); // DEBUG
      await queryRunner.rollbackTransaction();
      throw err;
    } finally {
      await queryRunner.release();
    }
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
    timezone?: string,
  ): Promise<Shift> {
    // Store the time-of-day as-is on a fixed base date. These are recurring
    // shift templates — the hour:minute is what matters, not a specific UTC
    // instant. Converting to UTC would shift the displayed time and break
    // across DST boundaries.
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

    await this.syncShiftRoles(manager, shift.id, s.assigned_roles);
    return shift;
  }

  /**
   * In-place update of an existing Shift from an InlineShiftDto. Mirrors the
   * field-derivation logic in createShiftFromInline but PRESERVES the shift's
   * id, so every downstream foreign key (employee_shifts.shift_id,
   * station_shift_assignments.shift_id, etc.) keeps pointing at the same row.
   *
   * Shift role rows are replaced (delete-all + re-create) because they're
   * pure derived data — no other table references a shift_role.id.
   */
  private async applyShiftInlineFields(
    manager: typeof this.dataSource.manager,
    shift: Shift,
    s: InlineShiftDto,
  ): Promise<void> {
    const baseDate = '1970-01-01';
    shift.name = s.name;
    shift.start_at = new Date(`${baseDate}T${s.start_time}:00Z`);
    shift.end_at = new Date(`${baseDate}T${s.end_time}:00Z`);
    shift.recurrence_type = s.recurrence
      ? (RECURRENCE_MAP[s.recurrence] ?? 'ONE_TIME')
      : 'ONE_TIME';
    shift.recurrence_days = s.custom_days?.length
      ? s.custom_days
          .map((d) => DAY_MAP[d.toLowerCase()])
          .filter(Boolean)
          .join(',')
      : null;
    if (s.duration === 'date-range') {
      shift.recurrence_start_date = s.duration_start_date
        ? new Date(s.duration_start_date)
        : null;
      shift.recurrence_end_date = s.duration_end_date
        ? new Date(s.duration_end_date)
        : null;
    } else {
      shift.recurrence_start_date = null;
      shift.recurrence_end_date = null;
    }
    await manager.save(Shift, shift);
    await this.syncShiftRoles(manager, shift.id, s.assigned_roles);
  }

  /**
   * Replace the ShiftRole rows for a given shift to match assigned_roles.
   * Accepts provider_role UUIDs with fallback to code-based lookup.
   * Unknown identifiers are silently skipped (same as the original create
   * behavior) rather than failing the whole transaction — a missing role
   * shouldn't block an otherwise-valid shift save.
   */
  private async syncShiftRoles(
    manager: typeof this.dataSource.manager,
    shiftId: string,
    assignedRoles?: string[],
  ): Promise<void> {
    await manager.delete(ShiftRole, { shift_id: shiftId });
    if (!assignedRoles?.length) return;
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    for (const identifier of assignedRoles) {
      const isUuid = uuidRegex.test(identifier);
      const role = isUuid
        ? await this.providerRoleRepository.findOne({
            where: { id: identifier },
          })
        : await this.providerRoleRepository.findOne({
            where: { code: identifier },
          });
      if (role) {
        await manager.save(
          ShiftRole,
          manager.create(ShiftRole, {
            shift_id: shiftId,
            provider_role_id: role.id,
          }),
        );
      }
    }
  }
}
