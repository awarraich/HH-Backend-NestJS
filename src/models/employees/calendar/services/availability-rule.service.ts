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

  async create(
    userId: string,
    dto: CreateAvailabilityRuleDto,
  ): Promise<AvailabilityRule> {
    const rule = this.availabilityRuleRepository.create({
      user_id: userId,
      organization_id: dto.organization_id ?? null,
      day_of_week: dto.day_of_week,
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

    // Remove existing rules for this user + org scope
    const deleteQb = this.availabilityRuleRepository
      .createQueryBuilder()
      .delete()
      .where('user_id = :userId', { userId });

    if (orgId) {
      deleteQb.andWhere('organization_id = :orgId', { orgId });
    } else {
      deleteQb.andWhere('organization_id IS NULL');
    }
    await deleteQb.execute();

    if (dto.rules.length === 0) return [];

    const entities = dto.rules.map((rule) =>
      this.availabilityRuleRepository.create({
        user_id: userId,
        organization_id: orgId,
        day_of_week: rule.day_of_week,
        start_time: rule.start_time,
        end_time: rule.end_time,
        is_available: rule.is_available ?? true,
        shift_type: rule.shift_type ?? null,
        effective_from: rule.effective_from ? new Date(rule.effective_from) : null,
        effective_until: rule.effective_until ? new Date(rule.effective_until) : null,
      }),
    );

    return this.availabilityRuleRepository.save(entities);
  }

  async remove(userId: string, id: string): Promise<void> {
    const rule = await this.availabilityRuleRepository.findOne({
      where: { id, user_id: userId },
    });
    if (!rule) throw new NotFoundException('Availability rule not found');
    await this.availabilityRuleRepository.remove(rule);
  }
}
