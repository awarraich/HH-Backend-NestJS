import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, FindOptionsWhere, LessThanOrEqual, MoreThanOrEqual } from 'typeorm';
import { CalendarEvent } from '../entities/calendar-event.entity';
import { CreateCalendarEventDto } from '../dto/create-calendar-event.dto';
import { UpdateCalendarEventDto } from '../dto/update-calendar-event.dto';
import { QueryCalendarEventDto } from '../dto/query-calendar-event.dto';

@Injectable()
export class CalendarEventService {
  constructor(
    @InjectRepository(CalendarEvent)
    private readonly calendarEventRepository: Repository<CalendarEvent>,
  ) {}

  async create(
    userId: string,
    dto: CreateCalendarEventDto,
  ): Promise<CalendarEvent> {
    if (new Date(dto.end_at) <= new Date(dto.start_at)) {
      throw new BadRequestException('end_at must be after start_at');
    }

    const event = this.calendarEventRepository.create({
      user_id: userId,
      organization_id: dto.organization_id ?? null,
      title: dto.title,
      description: dto.description ?? null,
      start_at: new Date(dto.start_at),
      end_at: new Date(dto.end_at),
      all_day: dto.all_day ?? false,
      location: dto.location ?? null,
      event_type: dto.event_type ?? 'general',
      color: dto.color ?? null,
      recurrence_rule: dto.recurrence_rule ?? null,
      recurrence_end_date: dto.recurrence_end_date ? new Date(dto.recurrence_end_date) : null,
      timezone: dto.timezone ?? 'America/Los_Angeles',
    });

    return this.calendarEventRepository.save(event);
  }

  async findAll(
    userId: string,
    query: QueryCalendarEventDto,
  ): Promise<{ data: CalendarEvent[]; total: number; page: number; limit: number }> {
    const page = query.page ?? 1;
    const limit = query.limit ?? 50;

    const where: FindOptionsWhere<CalendarEvent> = { user_id: userId };

    if (query.organization_id) {
      where.organization_id = query.organization_id;
    }
    if (query.event_type) {
      where.event_type = query.event_type;
    }
    if (query.status) {
      where.status = query.status;
    }

    const qb = this.calendarEventRepository
      .createQueryBuilder('e')
      .where('e.user_id = :userId', { userId });

    if (query.organization_id) {
      qb.andWhere('e.organization_id = :orgId', { orgId: query.organization_id });
    }
    if (query.event_type) {
      qb.andWhere('e.event_type = :eventType', { eventType: query.event_type });
    }
    if (query.status) {
      qb.andWhere('e.status = :status', { status: query.status });
    }
    if (query.from_date) {
      qb.andWhere('e.end_at >= :fromDate', { fromDate: query.from_date });
    }
    if (query.to_date) {
      qb.andWhere('e.start_at <= :toDate', { toDate: query.to_date });
    }

    qb.orderBy('e.start_at', 'ASC')
      .skip((page - 1) * limit)
      .take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(userId: string, id: string): Promise<CalendarEvent> {
    const event = await this.calendarEventRepository.findOne({
      where: { id, user_id: userId },
    });
    if (!event) throw new NotFoundException('Calendar event not found');
    return event;
  }

  async update(
    userId: string,
    id: string,
    dto: UpdateCalendarEventDto,
  ): Promise<CalendarEvent> {
    const event = await this.findOne(userId, id);

    if (dto.start_at && dto.end_at && new Date(dto.end_at) <= new Date(dto.start_at)) {
      throw new BadRequestException('end_at must be after start_at');
    }
    if (dto.start_at && !dto.end_at && new Date(event.end_at) <= new Date(dto.start_at)) {
      throw new BadRequestException('end_at must be after start_at');
    }
    if (!dto.start_at && dto.end_at && new Date(dto.end_at) <= new Date(event.start_at)) {
      throw new BadRequestException('end_at must be after start_at');
    }

    Object.assign(event, {
      ...(dto.title !== undefined && { title: dto.title }),
      ...(dto.description !== undefined && { description: dto.description }),
      ...(dto.start_at !== undefined && { start_at: new Date(dto.start_at) }),
      ...(dto.end_at !== undefined && { end_at: new Date(dto.end_at) }),
      ...(dto.all_day !== undefined && { all_day: dto.all_day }),
      ...(dto.location !== undefined && { location: dto.location }),
      ...(dto.event_type !== undefined && { event_type: dto.event_type }),
      ...(dto.color !== undefined && { color: dto.color }),
      ...(dto.recurrence_rule !== undefined && { recurrence_rule: dto.recurrence_rule }),
      ...(dto.recurrence_end_date !== undefined && {
        recurrence_end_date: dto.recurrence_end_date ? new Date(dto.recurrence_end_date) : null,
      }),
      ...(dto.timezone !== undefined && { timezone: dto.timezone }),
      ...(dto.status !== undefined && { status: dto.status }),
    });

    return this.calendarEventRepository.save(event);
  }

  async remove(userId: string, id: string): Promise<void> {
    const event = await this.findOne(userId, id);
    await this.calendarEventRepository.remove(event);
  }

  async findMySchedule(
    userId: string,
    fromDate?: string,
    toDate?: string,
  ): Promise<CalendarEvent[]> {
    const qb = this.calendarEventRepository
      .createQueryBuilder('e')
      .where('e.user_id = :userId', { userId })
      .andWhere('e.status = :status', { status: 'active' });

    if (fromDate) {
      qb.andWhere('e.end_at >= :fromDate', { fromDate });
    }
    if (toDate) {
      qb.andWhere('e.start_at <= :toDate', { toDate });
    }

    qb.orderBy('e.start_at', 'ASC');
    return qb.getMany();
  }
}
