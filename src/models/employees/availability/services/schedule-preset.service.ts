import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SchedulePreset } from '../entities/schedule-preset.entity';
import { CreateSchedulePresetDto } from '../dto/create-schedule-preset.dto';
import { UpdateSchedulePresetDto } from '../dto/update-schedule-preset.dto';

@Injectable()
export class SchedulePresetService {
  constructor(
    @InjectRepository(SchedulePreset)
    private readonly presetRepository: Repository<SchedulePreset>,
  ) {}

  async findByUser(userId: string): Promise<SchedulePreset[]> {
    return this.presetRepository.find({
      where: { user_id: userId },
      order: { created_at: 'ASC' },
    });
  }

  async create(
    userId: string,
    dto: CreateSchedulePresetDto,
  ): Promise<SchedulePreset> {
    const preset = this.presetRepository.create({
      user_id: userId,
      name: dto.name,
      week_pattern: dto.week_pattern,
    });
    return this.presetRepository.save(preset);
  }

  async update(
    userId: string,
    id: string,
    dto: UpdateSchedulePresetDto,
  ): Promise<SchedulePreset> {
    const preset = await this.presetRepository.findOne({
      where: { id, user_id: userId },
    });
    if (!preset) throw new NotFoundException('Schedule preset not found');

    if (dto.name !== undefined) preset.name = dto.name;
    if (dto.week_pattern !== undefined) preset.week_pattern = dto.week_pattern;

    return this.presetRepository.save(preset);
  }

  async remove(userId: string, id: string): Promise<void> {
    const preset = await this.presetRepository.findOne({
      where: { id, user_id: userId },
    });
    if (!preset) throw new NotFoundException('Schedule preset not found');
    await this.presetRepository.remove(preset);
  }
}
