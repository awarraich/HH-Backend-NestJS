import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { Shift } from '../entities/shift.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { CreateShiftDto } from '../dto/create-shift.dto';
import { UpdateShiftDto } from '../dto/update-shift.dto';
import { QueryShiftDto } from '../dto/query-shift.dto';

@Injectable()
export class ShiftService {
  constructor(
    @InjectRepository(Shift)
    private readonly shiftRepository: Repository<Shift>,
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
      .where('s.organization_id = :organizationId', { organizationId });

    // Date-range overlap test. Inputs may be either a date-only ('YYYY-MM-DD')
    // or a full timestamp. For date-only, expand to start-of-day / end-of-day
    // and do not rely on `new Date(...)` (which interprets bare dates as UTC
    // midnight and clashes with our `timestamp` (no tz) column).
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

    if (fromBound) {
      qb.andWhere('s.end_at > :fromBound', { fromBound });
    }
    if (toBound) {
      qb.andWhere('s.start_at < :toBound', { toBound });
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
      relations: ['employeeShifts', 'employeeShifts.employee', 'employeeShifts.employee.user'],
    });
    if (!shift) throw new NotFoundException('Shift not found');
    return shift;
  }

  async create(organizationId: string, dto: CreateShiftDto, userId: string): Promise<Shift> {
    await this.ensureAccess(organizationId, userId);
    const shift = this.shiftRepository.create({
      organization_id: organizationId,
      start_at: new Date(dto.start_at),
      end_at: new Date(dto.end_at),
      shift_type: dto.shift_type ?? null,
      name: dto.name ?? null,
      status: 'ACTIVE',
      recurrence_type: dto.recurrence_type ?? 'ONE_TIME',
      recurrence_days: dto.recurrence_days?.length ? dto.recurrence_days.join(',') : null,
      recurrence_start_date: dto.recurrence_start_date ? new Date(dto.recurrence_start_date) : null,
      recurrence_end_date: dto.recurrence_end_date ? new Date(dto.recurrence_end_date) : null,
    });
    return this.shiftRepository.save(shift);
  }

  async update(
    organizationId: string,
    shiftId: string,
    dto: UpdateShiftDto,
    userId: string,
  ): Promise<Shift> {
    await this.ensureAccess(organizationId, userId);
    const shift = await this.findOne(organizationId, shiftId, userId);
    if (dto.start_at !== undefined) shift.start_at = new Date(dto.start_at);
    if (dto.end_at !== undefined) shift.end_at = new Date(dto.end_at);
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
    return this.shiftRepository.save(shift);
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
      .where('s.organization_id = :organizationId', { organizationId })
      .andWhere('(LOWER(s.name) LIKE :q OR LOWER(s.shift_type) LIKE :q)', {
        q: `%${trimmed.toLowerCase()}%`,
      })
      .orderBy('s.start_at', 'ASC')
      .take(limit)
      .getMany();
  }
}
