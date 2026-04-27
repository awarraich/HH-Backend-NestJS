import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WorkPreference } from '../entities/work-preference.entity';
import { UpdateWorkPreferenceDto } from '../dto/update-work-preference.dto';

@Injectable()
export class WorkPreferenceService {
  constructor(
    @InjectRepository(WorkPreference)
    private readonly workPreferenceRepository: Repository<WorkPreference>,
  ) {}

  async findOrCreate(userId: string): Promise<WorkPreference> {
    let pref = await this.workPreferenceRepository.findOne({
      where: { user_id: userId },
    });
    if (!pref) {
      pref = this.workPreferenceRepository.create({ user_id: userId });
      pref = await this.workPreferenceRepository.save(pref);
    }
    return pref;
  }

  async update(
    userId: string,
    dto: UpdateWorkPreferenceDto,
  ): Promise<WorkPreference> {
    let pref = await this.findOrCreate(userId);

    const fields: (keyof UpdateWorkPreferenceDto)[] = [
      'max_hours_per_week', 'preferred_shift_type',
      'available_for_overtime', 'available_for_on_call',
      'min_rest_hours', 'max_consecutive_days', 'max_hours_per_day',
      'double_shift_preference', 'double_shift_conditions',
      'work_type', 'travel_radius', 'has_own_vehicle', 'use_company_vehicle',
      'preferred_areas', 'facilities', 'weekly_notes',
      'availability_ui_by_org',
    ];

    const updates: Record<string, unknown> = {};
    for (const field of fields) {
      if (dto[field] !== undefined) updates[field] = dto[field];
    }
    Object.assign(pref, updates);

    return this.workPreferenceRepository.save(pref);
  }
}
