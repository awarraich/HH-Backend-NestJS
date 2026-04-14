import { Injectable, NotFoundException } from '@nestjs/common';
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

  /**
   * Derive day_of_week from a YYYY-MM-DD string.
   * JS Date.getUTCDay() returns 0 = SUN … 6 = SAT, matching our convention.
   */
  private deriveDayOfWeek(dateStr: string): number {
    return new Date(`${dateStr}T00:00:00Z`).getUTCDay();
  }

  async create(
    userId: string,
    dto: CreateAvailabilityRuleDto,
  ): Promise<AvailabilityRule> {
    const dayOfWeek = dto.date
      ? this.deriveDayOfWeek(dto.date)
      : (dto.day_of_week ?? 0);

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

  async bulkUpsert(
    userId: string,
    dto: BulkUpsertAvailabilityDto,
  ): Promise<AvailabilityRule[]> {
    const orgId = dto.organization_id ?? null;

    // Separate incoming rules into date-specific vs recurring
    const hasDateRules = dto.rules.some((r) => r.date);
    const hasRecurringRules = dto.rules.some((r) => !r.date);

    // Remove existing rules for this user + org scope, scoped by type
    const buildDeleteQb = (dateSpecific: boolean) => {
      const qb = this.availabilityRuleRepository
        .createQueryBuilder()
        .delete()
        .where('user_id = :userId', { userId });

      if (orgId) {
        qb.andWhere('organization_id = :orgId', { orgId });
      } else {
        qb.andWhere('organization_id IS NULL');
      }

      if (dateSpecific) {
        qb.andWhere('date IS NOT NULL');
      } else {
        qb.andWhere('date IS NULL');
      }
      return qb;
    };

    if (hasDateRules) await buildDeleteQb(true).execute();
    if (hasRecurringRules) await buildDeleteQb(false).execute();

    if (dto.rules.length === 0) return [];

    const entities = dto.rules.map((rule) => {
      const dayOfWeek = rule.date
        ? this.deriveDayOfWeek(rule.date)
        : (rule.day_of_week ?? 0);

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

  async findByUserAndDate(
    userId: string,
    date: string,
    organizationId?: string | null,
  ): Promise<AvailabilityRule[]> {
    const qb = this.availabilityRuleRepository
      .createQueryBuilder('r')
      .where('r.user_id = :userId', { userId })
      .andWhere('r.date = :date', { date });

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
}
