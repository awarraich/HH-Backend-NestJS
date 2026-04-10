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

    Object.assign(pref, {
      ...(dto.max_hours_per_week !== undefined && { max_hours_per_week: dto.max_hours_per_week }),
      ...(dto.preferred_shift_type !== undefined && { preferred_shift_type: dto.preferred_shift_type }),
      ...(dto.available_for_overtime !== undefined && { available_for_overtime: dto.available_for_overtime }),
      ...(dto.available_for_on_call !== undefined && { available_for_on_call: dto.available_for_on_call }),
    });

    return this.workPreferenceRepository.save(pref);
  }
}
