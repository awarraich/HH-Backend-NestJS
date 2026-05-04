import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AvailabilityRule } from '../entities/availability-rule.entity';
import { CreateAvailabilityRuleDto } from '../dto/create-availability-rule.dto';
import { BulkUpsertAvailabilityDto } from '../dto/bulk-upsert-availability.dto';

@Injectable()
export class AvailabilityRuleService {
  constructor(
    @InjectRepository(AvailabilityRule)
    private readonly availabilityRuleRepository: Repository<AvailabilityRule>,
  ) {}

  /**
   * Derive day_of_week (0=SUN … 6=SAT) from a YYYY-MM-DD date string.
   * Always uses UTC so timezone differences never shift the day.
   */
  private deriveDayOfWeek(dateStr: string): number {
    return new Date(`${dateStr}T00:00:00Z`).getUTCDay();
  }

  async findByUser(
    userId: string,
    organizationId?: string | null,
  ): Promise<AvailabilityRule[]> {
    const qb = this.availabilityRuleRepository
      .createQueryBuilder('r')
      .where('r.user_id = :userId', { userId });

    if (organizationId) {
      qb.andWhere('r.organization_id = :orgId', { orgId: organizationId });
    }

    qb.orderBy('r.day_of_week', 'ASC').addOrderBy('r.start_time', 'ASC');
    return qb.getMany();
  }

  async create(
    userId: string,
    dto: CreateAvailabilityRuleDto,
  ): Promise<AvailabilityRule> {
    // Auto-derive day_of_week from date when date is provided
    const dayOfWeek = dto.date
      ? this.deriveDayOfWeek(dto.date)
      : dto.day_of_week;

    const rule = this.availabilityRuleRepository.create({
      user_id: userId,
      organization_id: dto.organization_id ?? null,
      date: dto.date ?? null,
      day_of_week: dayOfWeek,
      start_time: dto.start_time,
      end_time: dto.end_time,
      is_available: dto.is_available ?? true,
      shift_type: dto.shift_type ?? null,
      effective_from: dto.effective_from ? new Date(dto.effective_from) : null,
      effective_until: dto.effective_until ? new Date(dto.effective_until) : null,
    });
    return this.availabilityRuleRepository.save(rule);
  }

  private validateNoOverlaps(rules: CreateAvailabilityRuleDto[]): void {
    // Group rules by day_of_week + shift_type
    const groups: Record<string, { start_time: string; end_time: string }[]> = {};
    for (const rule of rules) {
      if (rule.is_available === false) continue;
      const key = `${rule.day_of_week}:${rule.shift_type ?? 'morning'}`;
      if (!groups[key]) groups[key] = [];
      groups[key].push({ start_time: rule.start_time, end_time: rule.end_time });
    }

    for (const [key, segments] of Object.entries(groups)) {
      // Check start equals end
      for (let i = 0; i < segments.length; i++) {
        if (segments[i].start_time === segments[i].end_time) {
          throw new BadRequestException(
            `Invalid time range for ${key}: start and end times cannot be equal`,
          );
        }
      }
      // Check pairwise overlap
      for (let i = 0; i < segments.length; i++) {
        for (let j = i + 1; j < segments.length; j++) {
          const a = segments[i];
          const b = segments[j];
          const aS = this.timeToMinutes(a.start_time);
          const aE = this.timeToMinutes(a.end_time);
          const bS = this.timeToMinutes(b.start_time);
          const bE = this.timeToMinutes(b.end_time);
          if (aS < aE && bS < bE && aS < bE && bS < aE) {
            throw new BadRequestException(
              `Overlapping time ranges for ${key}: ${a.start_time}-${a.end_time} and ${b.start_time}-${b.end_time}`,
            );
          }
        }
      }
    }
  }

  private timeToMinutes(t: string): number {
    const parts = t.split(':').map(Number);
    return (parts[0] ?? 0) * 60 + (parts[1] ?? 0);
  }

  async bulkUpsert(
    userId: string,
    dto: BulkUpsertAvailabilityDto,
  ): Promise<AvailabilityRule[]> {
    const orgId = dto.organization_id ?? null;

    // Refuse empty-body PUTs. The previous contract deleted all weekly
    // rules first and only then short-circuited on empty input, which
    // meant a frontend bug or a truncated request body silently wiped
    // the user's entire weekly availability. Callers that genuinely
    // want to clear availability should delete rules individually via
    // DELETE /availability/:id — empty bulk upsert is never intentional.
    if (dto.rules.length === 0) {
      throw new BadRequestException(
        'Cannot save an empty availability list. Provide at least one rule, or delete individual rules with DELETE /availability/:id.',
      );
    }

    this.validateNoOverlaps(dto.rules);

    // Only remove weekly rules (effective_from IS NULL) for this user + org scope
    const deleteQb = this.availabilityRuleRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId })
      .andWhere('effective_from IS NULL');

    if (orgId) {
      deleteQb.andWhere('organization_id = :orgId', { orgId });
    } else {
      deleteQb.andWhere('organization_id IS NULL');
    }
    await deleteQb.execute();

    const entities = dto.rules.map((rule) => {
      const dayOfWeek = rule.date
        ? this.deriveDayOfWeek(rule.date)
        : rule.day_of_week;

      return this.availabilityRuleRepository.create({
        user_id: userId,
        organization_id: orgId,
        date: rule.date ?? null,
        day_of_week: dayOfWeek,
        start_time: rule.start_time,
        end_time: rule.end_time,
        is_available: rule.is_available ?? true,
        shift_type: rule.shift_type ?? null,
        effective_from: rule.effective_from ? new Date(rule.effective_from) : null,
        effective_until: rule.effective_until ? new Date(rule.effective_until) : null,
      });
    });

    return this.availabilityRuleRepository.save(entities);
  }

  async upsertDateOverride(
    userId: string,
    date: string,
    dto: BulkUpsertAvailabilityDto,
  ): Promise<AvailabilityRule[]> {
    const orgId = dto.organization_id ?? null;

    this.validateNoOverlaps(dto.rules);

    // Remove existing override rules for this specific date
    const deleteQb = this.availabilityRuleRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId })
      .andWhere('effective_from = :date', { date });

    if (orgId) {
      deleteQb.andWhere('organization_id = :orgId', { orgId });
    } else {
      deleteQb.andWhere('organization_id IS NULL');
    }
    await deleteQb.execute();

    if (dto.rules.length === 0) return [];

    // The URL date param is the source of truth — always derive day_of_week
    // from it so a frontend timezone bug can never store the wrong day.
    const dayOfWeek = this.deriveDayOfWeek(date);

    const entities = dto.rules.map((rule) =>
      this.availabilityRuleRepository.create({
        user_id: userId,
        organization_id: orgId,
        date,
        day_of_week: dayOfWeek,
        start_time: rule.start_time,
        end_time: rule.end_time,
        is_available: rule.is_available ?? true,
        shift_type: rule.shift_type ?? null,
        effective_from: new Date(date),
        effective_until: new Date(date),
      }),
    );

    return this.availabilityRuleRepository.save(entities);
  }

  async removeDateOverride(
    userId: string,
    date: string,
    organizationId?: string | null,
  ): Promise<void> {
    const deleteQb = this.availabilityRuleRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId })
      .andWhere('effective_from = :date', { date });

    if (organizationId) {
      deleteQb.andWhere('organization_id = :orgId', { orgId: organizationId });
    } else {
      deleteQb.andWhere('organization_id IS NULL');
    }
    await deleteQb.execute();
  }

  async findByUserAndDate(
    userId: string,
    date: string,
    organizationId?: string | null,
  ): Promise<AvailabilityRule[]> {
    const dayOfWeek = new Date(`${date}T00:00:00Z`).getUTCDay();

    const qb = this.availabilityRuleRepository
      .createQueryBuilder('r')
      .where('r.user_id = :userId', { userId })
      .andWhere(
        '(r.date = :date OR (r.date IS NULL AND r.day_of_week = :dayOfWeek))',
        { date, dayOfWeek },
      )
      .andWhere(
        '(r.effective_from IS NULL OR r.effective_from <= :date)',
        { date },
      )
      .andWhere(
        '(r.effective_until IS NULL OR r.effective_until >= :date)',
        { date },
      );

    if (organizationId) {
      qb.andWhere('r.organization_id = :orgId', { orgId: organizationId });
    }

    qb.orderBy('r.start_time', 'ASC');
    return qb.getMany();
  }

  async remove(userId: string, id: string): Promise<void> {
    const rule = await this.availabilityRuleRepository.findOne({
      where: { id, user_id: userId },
    });
    if (!rule) throw new NotFoundException('Availability rule not found');
    await this.availabilityRuleRepository.remove(rule);
  }

  /**
   * Upserts a single weekly availability rule for a user, scoped by
   * day_of_week (and optionally organization). Used by the Google Chat
   * agent's `setAvailabilityRule` tool — the agent semantics are "I'm
   * available Tuesdays 9–5", not "add this slot to my Tuesday."
   *
   * Replaces ALL non-date-specific weekly rules for that user+day in the
   * same scope before inserting. Multi-slot weekly schedules (split shifts
   * within one day) are not preserved by this path — callers expecting
   * that should use `bulkUpsert` from the web UI instead.
   *
   * Date-specific rules (with `effective_from` set) are NOT touched.
   */
  async upsertWeeklyRuleForUser(
    userId: string,
    dto: {
      organization_id?: string | null;
      day_of_week: number;
      start_time: string;
      end_time: string;
      is_available?: boolean;
      shift_type?: string | null;
    },
  ): Promise<AvailabilityRule> {
    if (dto.day_of_week < 0 || dto.day_of_week > 6) {
      throw new BadRequestException('day_of_week must be 0 (Sun) through 6 (Sat)');
    }
    if (dto.start_time === dto.end_time) {
      throw new BadRequestException(
        'start_time and end_time cannot be equal',
      );
    }

    const orgId = dto.organization_id ?? null;
    const deleteQb = this.availabilityRuleRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId })
      .andWhere('day_of_week = :dow', { dow: dto.day_of_week })
      .andWhere('date IS NULL')
      .andWhere('effective_from IS NULL');

    if (orgId) {
      deleteQb.andWhere('organization_id = :orgId', { orgId });
    } else {
      deleteQb.andWhere('organization_id IS NULL');
    }
    await deleteQb.execute();

    const rule = this.availabilityRuleRepository.create({
      user_id: userId,
      organization_id: orgId,
      date: null,
      day_of_week: dto.day_of_week,
      start_time: dto.start_time,
      end_time: dto.end_time,
      is_available: dto.is_available ?? true,
      shift_type: dto.shift_type ?? null,
      effective_from: null,
      effective_until: null,
    });
    return this.availabilityRuleRepository.save(rule);
  }
}
