import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Shift } from '../entities/shift.entity';
import { ShiftRole } from '../entities/shift-role.entity';
import { ProviderRole } from '../../../employees/entities/provider-role.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateShiftDto } from '../dto/create-shift.dto';
import { UpdateShiftDto } from '../dto/update-shift.dto';
import { QueryShiftDto } from '../dto/query-shift.dto';
import { localToUtc } from '../../../../mcp/tools/scheduling/timezone';

@Injectable()
export class ShiftService {
  constructor(
    @InjectRepository(Shift)
    private readonly shiftRepository: Repository<Shift>,
    @InjectRepository(ShiftRole)
    private readonly shiftRoleRepository: Repository<ShiftRole>,
    @InjectRepository(ProviderRole)
    private readonly providerRoleRepository: Repository<ProviderRole>,
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

  async findAll(
    organizationId: string,
    query: QueryShiftDto,
    userId: string,
  ): Promise<{ data: Shift[]; total: number; page: number; limit: number }> {
    await this.ensureAccess(organizationId, userId);
    const { page = 1, limit = 20, from_date, to_date, shift_type, status, recurrence_type } = query;
    const skip = (page - 1) * limit;

    const qb = this.shiftRepository
      .createQueryBuilder('s')
      .leftJoinAndSelect('s.shiftRoles', 'sr')
      .leftJoinAndSelect('sr.providerRole', 'pr')
      .where('s.organization_id = :organizationId', { organizationId });

    // When a date range is requested (calendar views), also return the
    // employee_shifts booked inside that range so the client can render
    // assignments per-day without a second round-trip. Filter is applied
    // in the JOIN so shifts with zero bookings in range still appear.
    if (from_date || to_date) {
      qb.leftJoinAndSelect(
        's.employeeShifts',
        'es',
        [
          from_date ? 'es.scheduled_date >= :esFrom' : null,
          to_date ? 'es.scheduled_date <= :esTo' : null,
        ].filter(Boolean).join(' AND ') || '1=1',
        { esFrom: from_date, esTo: to_date },
      )
        .leftJoinAndSelect('es.employee', 'esEmp')
        .leftJoinAndSelect('esEmp.user', 'esEmpUser')
        .leftJoinAndSelect('esEmp.providerRole', 'esEmpRole')
        .leftJoinAndSelect('es.station', 'esStation')
        .leftJoinAndSelect('es.department', 'esDept');
    }

    // Date filtering: two cases to handle:
    // 1. ONE_TIME shifts — match by timestamp overlap (start_at/end_at in the requested range)
    // 2. Recurring shifts (FULL_WEEK, WEEKDAYS, WEEKENDS, CUSTOM) — stored with base dates
    //    like 1970-01-01; match by recurrence pattern + optional recurrence date bounds
    const isDateOnly = (v: string) => /^\d{4}-\d{2}-\d{2}$/.test(v);
    const fromBound = from_date
      ? isDateOnly(from_date)
        ? `${from_date} 00:00:00`
        : from_date
      : null;
    const toBound = to_date
      ? isDateOnly(to_date)
        ? `${to_date} 23:59:59`
        : to_date
      : null;

    if (fromBound || toBound) {
      // Build a compound condition: (one-time overlap) OR (recurring that applies)
      const conditions: string[] = [];
      const params: Record<string, unknown> = {};

      // ONE_TIME: standard timestamp overlap
      const oneTimeParts: string[] = ["s.recurrence_type = 'ONE_TIME'"];
      if (fromBound) { oneTimeParts.push('s.end_at > :fromBound'); params.fromBound = fromBound; }
      if (toBound) { oneTimeParts.push('s.start_at < :toBound'); params.toBound = toBound; }
      conditions.push(`(${oneTimeParts.join(' AND ')})`);

      // Recurring: always include, but respect recurrence date bounds if set
      const recurParts: string[] = ["s.recurrence_type != 'ONE_TIME'"];
      if (fromBound) {
        recurParts.push('(s.recurrence_end_date IS NULL OR s.recurrence_end_date >= :fromDate)');
        params.fromDate = from_date;
      }
      if (toBound) {
        recurParts.push('(s.recurrence_start_date IS NULL OR s.recurrence_start_date <= :toDate)');
        params.toDate = to_date;
      }
      conditions.push(`(${recurParts.join(' AND ')})`);

      qb.andWhere(`(${conditions.join(' OR ')})`, params);
    }
    if (shift_type) {
      qb.andWhere('UPPER(s.shift_type) = UPPER(:shift_type)', { shift_type });
    }
    if (status) {
      qb.andWhere('UPPER(s.status) = UPPER(:status)', { status });
    }
    if (recurrence_type) {
      qb.andWhere('UPPER(s.recurrence_type) = UPPER(:recurrence_type)', { recurrence_type });
    }
    qb.orderBy('s.start_at', 'ASC').skip(skip).take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(organizationId: string, shiftId: string, userId: string): Promise<Shift> {
    await this.ensureAccess(organizationId, userId);
    const shift = await this.shiftRepository.findOne({
      where: { id: shiftId, organization_id: organizationId },
      relations: [
        'employeeShifts', 'employeeShifts.employee', 'employeeShifts.employee.user',
        'shiftRoles', 'shiftRoles.providerRole',
      ],
    });
    if (!shift) throw new NotFoundException('Shift not found');
    return shift;
  }

  async create(organizationId: string, dto: CreateShiftDto, userId: string): Promise<Shift> {
    await this.ensureAccess(organizationId, userId);
    const tz = dto.timezone;
    const toDate = (v: string) => (tz ? localToUtc(v, tz) : new Date(v));
    const shift = this.shiftRepository.create({
      organization_id: organizationId,
      start_at: toDate(dto.start_at),
      end_at: toDate(dto.end_at),
      shift_type: dto.shift_type ?? null,
      name: dto.name ?? null,
      status: 'ACTIVE',
      recurrence_type: dto.recurrence_type ?? 'ONE_TIME',
      recurrence_days: dto.recurrence_days?.length ? dto.recurrence_days.join(',') : null,
      recurrence_start_date: dto.recurrence_start_date ? new Date(dto.recurrence_start_date) : null,
      recurrence_end_date: dto.recurrence_end_date ? new Date(dto.recurrence_end_date) : null,
    });
    const saved = await this.shiftRepository.save(shift);
    if (dto.assigned_roles?.length) {
      await this.syncShiftRoles(saved.id, dto.assigned_roles);
    }
    return saved;
  }

  async update(
    organizationId: string,
    shiftId: string,
    dto: UpdateShiftDto,
    userId: string,
  ): Promise<Shift> {
    await this.ensureAccess(organizationId, userId);
    const shift = await this.findOne(organizationId, shiftId, userId);
    const tz = dto.timezone;
    const toDate = (v: string) => (tz ? localToUtc(v, tz) : new Date(v));
    if (dto.start_at !== undefined) shift.start_at = toDate(dto.start_at);
    if (dto.end_at !== undefined) shift.end_at = toDate(dto.end_at);
    if (dto.shift_type !== undefined) shift.shift_type = dto.shift_type;
    if (dto.name !== undefined) shift.name = dto.name;
    if (dto.status !== undefined) shift.status = dto.status;
    if (dto.recurrence_type !== undefined) shift.recurrence_type = dto.recurrence_type;
    if (dto.recurrence_start_date !== undefined) {
      shift.recurrence_start_date = new Date(dto.recurrence_start_date);
    }
    if (dto.recurrence_end_date !== undefined) {
      shift.recurrence_end_date = new Date(dto.recurrence_end_date);
    }
    if (dto.recurrence_days !== undefined) {
      shift.recurrence_days = dto.recurrence_days?.length ? dto.recurrence_days.join(',') : null;
    }
    const saved = await this.shiftRepository.save(shift);
    if (dto.assigned_roles !== undefined) {
      await this.syncShiftRoles(saved.id, dto.assigned_roles ?? []);
    }
    return saved;
  }

  async remove(organizationId: string, shiftId: string, userId: string): Promise<void> {
    await this.ensureAccess(organizationId, userId);
    const shift = await this.findOne(organizationId, shiftId, userId);
    await this.shiftRepository.remove(shift);
  }

  /**
   * Free-text search across shift name and shift_type. Used by MCP tools
   * for autocomplete-style lookups; intentionally lighter than findAll.
   */
  async searchByText(
    organizationId: string,
    query: string,
    userId: string,
    limit = 25,
  ): Promise<Shift[]> {
    await this.ensureAccess(organizationId, userId);
    const trimmed = query.trim();
    if (!trimmed) return [];

    return this.shiftRepository
      .createQueryBuilder('s')
      .leftJoinAndSelect('s.shiftRoles', 'sr')
      .leftJoinAndSelect('sr.providerRole', 'pr')
      .where('s.organization_id = :organizationId', { organizationId })
      .andWhere('(LOWER(s.name) LIKE :q OR LOWER(s.shift_type) LIKE :q)', {
        q: `%${trimmed.toLowerCase()}%`,
      })
      .orderBy('s.start_at', 'ASC')
      .take(limit)
      .getMany();
  }

  /**
   * Sync the shift_roles junction for a given shift.
   * Accepts provider_role IDs (UUIDs). Falls back to code-based lookup
   * for non-UUID values to maintain backward compatibility.
   */
  private async syncShiftRoles(shiftId: string, roleIdentifiers: string[]): Promise<void> {
    await this.shiftRoleRepository.delete({ shift_id: shiftId });
    if (!roleIdentifiers.length) return;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    for (const identifier of roleIdentifiers) {
      const isUuid = uuidRegex.test(identifier);
      const role = isUuid
        ? await this.providerRoleRepository.findOne({ where: { id: identifier } })
        : await this.providerRoleRepository.findOne({ where: { code: identifier } });
      if (role) {
        await this.shiftRoleRepository.save(
          this.shiftRoleRepository.create({ shift_id: shiftId, provider_role_id: role.id }),
        );
      }
    }
  }
}
