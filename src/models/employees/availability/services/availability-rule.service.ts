import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Brackets } from 'typeorm';
import { AvailabilityRule } from '../entities/availability-rule.entity';
import { TimeOffRequest } from '../entities/time-off-request.entity';
import { CreateAvailabilityRuleDto } from '../dto/create-availability-rule.dto';
import { BulkUpsertAvailabilityDto } from '../dto/bulk-upsert-availability.dto';

export type AvailabilityCheckStatus = 'available' | 'unavailable' | 'unknown';

export interface AvailabilityCheckResult {
  status: AvailabilityCheckStatus;
  reason?: string;
  matched_rule?: {
    id: string;
    is_available: boolean;
    start_time: string;
    end_time: string;
    date: string | null;
    day_of_week: number | null;
  } | null;
  time_off?: {
    id: string;
    status: string;
    start_date: string;
    end_date: string;
  } | null;
}

@Injectable()
export class AvailabilityRuleService {
  constructor(
    @InjectRepository(AvailabilityRule)
    private readonly availabilityRuleRepository: Repository<AvailabilityRule>,
    @InjectRepository(TimeOffRequest)
    private readonly timeOffRepository: Repository<TimeOffRequest>,
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
      // Include rules pinned to this org AND rules saved without an org
      // (NULL = "applies to all orgs"). This matches what the employee
      // sees on their own portal and what `checkAvailabilityBulk` /
      // `loadAvailabilityForEmployee` already do — keeping the strict
      // equality version meant the org-side HR view found nothing for
      // employees who saved rules without an org pin.
      qb.andWhere(
        '(r.organization_id = :orgId OR r.organization_id IS NULL)',
        { orgId: organizationId },
      );
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
   * Vectorised availability check. Pulls relevant rules + time-off in two
   * bounded queries (`user_id IN (:...userIds)`) and evaluates each user
   * in memory — so a 50-employee picker costs the same DB round-trip as a
   * single-employee save-time guard.
   *
   * Decision precedence per user:
   *   1. Approved/pending time-off covering the date  → unavailable.
   *   2. Date-specific rule (`r.date = date`) wins over weekly rules.
   *   3. `is_available=false` rule overlapping the slot → unavailable.
   *   4. `is_available=true` rule fully covering the slot → available.
   *   5. `is_available=true` rule only partially covering → unavailable
   *      (with a "partial" reason).
   *   6. No matching rule, but user has rules elsewhere → unavailable
   *      (employee opted-in their schedule and didn't include this day).
   *   7. User has no rules at all → unknown (silent allow).
   *
   * Org-scoped lookup: union of `organization_id = orgId` and
   * `organization_id IS NULL` rules.
   */
  async checkAvailabilityBulk(
    userIds: string[],
    organizationId: string,
    date: string,
    startTime: string,
    endTime: string,
  ): Promise<Record<string, AvailabilityCheckResult>> {
    const result: Record<string, AvailabilityCheckResult> = {};
    if (userIds.length === 0) return result;

    const dow = this.deriveDayOfWeek(date);
    const startMin = this.timeToMinutes(startTime);
    const endMin = this.timeToMinutes(endTime);

    const orgClause = new Brackets((qb) => {
      qb.where('r.organization_id = :orgId', { orgId: organizationId })
        .orWhere('r.organization_id IS NULL');
    });
    const timeOffOrgClause = new Brackets((qb) => {
      qb.where('t.organization_id = :orgId', { orgId: organizationId })
        .orWhere('t.organization_id IS NULL');
    });

    const [rules, timeOffs, anyRulesRows] = await Promise.all([
      this.availabilityRuleRepository
        .createQueryBuilder('r')
        .where('r.user_id IN (:...userIds)', { userIds })
        .andWhere(orgClause)
        .andWhere(
          new Brackets((qb) => {
            qb.where('r.date = :date', { date })
              .orWhere('r.day_of_week = :dow', { dow });
          }),
        )
        .getMany(),
      this.timeOffRepository
        .createQueryBuilder('t')
        .where('t.user_id IN (:...userIds)', { userIds })
        .andWhere('t.status IN (:...statuses)', { statuses: ['approved', 'pending'] })
        .andWhere(timeOffOrgClause)
        .andWhere(':date BETWEEN t.start_date AND t.end_date', { date })
        .getMany(),
      this.availabilityRuleRepository
        .createQueryBuilder('r')
        .select('r.user_id', 'user_id')
        .where('r.user_id IN (:...userIds)', { userIds })
        .andWhere(orgClause)
        .groupBy('r.user_id')
        .getRawMany<{ user_id: string }>(),
    ]);

    const usersWithAnyRules = new Set(anyRulesRows.map((r) => r.user_id));

    const rulesByUser = new Map<string, AvailabilityRule[]>();
    for (const r of rules) {
      const arr = rulesByUser.get(r.user_id) ?? [];
      arr.push(r);
      rulesByUser.set(r.user_id, arr);
    }
    const timeOffByUser = new Map<string, TimeOffRequest>();
    for (const t of timeOffs) {
      if (!timeOffByUser.has(t.user_id)) timeOffByUser.set(t.user_id, t);
    }

    // Sentinel the frontend writes for "day off" overrides — `00:00 / 00:00
    // is_available=false`. Treat as full-day-blocked so the zero-length
    // range still trips the unavailable branch.
    const isFullDayOffSentinel = (r: AvailabilityRule): boolean =>
      !r.is_available && r.start_time.startsWith('00:00') && r.end_time.startsWith('00:00');

    const overlaps = (r: AvailabilityRule): boolean => {
      if (isFullDayOffSentinel(r)) return true;
      const rStart = this.timeToMinutes(r.start_time);
      const rEnd = this.timeToMinutes(r.end_time);
      const effectiveEnd = rEnd <= rStart ? rEnd + 24 * 60 : rEnd;
      const effectiveShiftEnd = endMin <= startMin ? endMin + 24 * 60 : endMin;
      return rStart < effectiveShiftEnd && startMin < effectiveEnd;
    };
    const covers = (r: AvailabilityRule): boolean => {
      const rStart = this.timeToMinutes(r.start_time);
      const rEnd = this.timeToMinutes(r.end_time);
      const effectiveEnd = rEnd <= rStart ? rEnd + 24 * 60 : rEnd;
      const effectiveShiftEnd = endMin <= startMin ? endMin + 24 * 60 : endMin;
      return rStart <= startMin && effectiveEnd >= effectiveShiftEnd;
    };

    const evaluate = (pool: AvailabilityRule[]): AvailabilityCheckResult | null => {
      const explicitUnavailable = pool.find((r) => !r.is_available && overlaps(r));
      if (explicitUnavailable) {
        return {
          status: 'unavailable',
          reason: isFullDayOffSentinel(explicitUnavailable)
            ? 'Employee marked this day as off.'
            : 'Employee marked themselves unavailable for this slot.',
          matched_rule: this.serializeRule(explicitUnavailable),
        };
      }
      const fullyCovering = pool.find((r) => r.is_available && covers(r));
      if (fullyCovering) {
        return { status: 'available', matched_rule: this.serializeRule(fullyCovering) };
      }
      const partialAvailable = pool.find((r) => r.is_available && overlaps(r));
      if (partialAvailable) {
        return {
          status: 'unavailable',
          reason: 'Employee is only available for part of this shift.',
          matched_rule: this.serializeRule(partialAvailable),
        };
      }
      return null;
    };

    for (const userId of userIds) {
      const t = timeOffByUser.get(userId);
      if (t) {
        result[userId] = {
          status: 'unavailable',
          reason:
            t.status === 'approved'
              ? 'Employee has approved time-off on this date.'
              : 'Employee has a pending time-off request on this date.',
          time_off: {
            id: t.id,
            status: t.status,
            start_date: typeof t.start_date === 'string' ? t.start_date : String(t.start_date),
            end_date: typeof t.end_date === 'string' ? t.end_date : String(t.end_date),
          },
        };
        continue;
      }

      const userRules = rulesByUser.get(userId) ?? [];
      const dateRules = userRules.filter((r) => r.date === date);
      const dowRules = userRules.filter((r) => !r.date && r.day_of_week === dow);

      const match = evaluate(dateRules) ?? evaluate(dowRules);
      if (match) {
        result[userId] = match;
        continue;
      }
      result[userId] = usersWithAnyRules.has(userId)
        ? {
            status: 'unavailable',
            reason: "Employee hasn't marked themselves available on this day.",
          }
        : { status: 'unknown' };
    }
    return result;
  }

  private serializeRule(r: AvailabilityRule): NonNullable<AvailabilityCheckResult['matched_rule']> {
    return {
      id: r.id,
      is_available: r.is_available,
      start_time: r.start_time,
      end_time: r.end_time,
      date: r.date,
      day_of_week: r.day_of_week,
    };
  }
}
