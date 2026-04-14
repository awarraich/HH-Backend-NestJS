import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { TimeOffRequest } from '../entities/time-off-request.entity';
import { CreateTimeOffRequestDto } from '../dto/create-time-off-request.dto';
import { QueryTimeOffRequestDto } from '../dto/query-time-off-request.dto';

@Injectable()
export class TimeOffRequestService {
  constructor(
    @InjectRepository(TimeOffRequest)
    private readonly timeOffRequestRepository: Repository<TimeOffRequest>,
  ) {}

  async create(
    userId: string,
    dto: CreateTimeOffRequestDto,
  ): Promise<TimeOffRequest> {
    if (dto.end_date < dto.start_date) {
      throw new BadRequestException('end_date must be on or after start_date');
    }

    const request = this.timeOffRequestRepository.create({
      user_id: userId,
      organization_id: dto.organization_id ?? null,
      start_date: dto.start_date,
      end_date: dto.end_date,
      reason: dto.reason ?? null,
    });
    return this.timeOffRequestRepository.save(request);
  }

  async findAll(
    userId: string,
    query: QueryTimeOffRequestDto,
  ): Promise<{ data: TimeOffRequest[]; total: number; page: number; limit: number }> {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;

    const qb = this.timeOffRequestRepository
      .createQueryBuilder('t')
      .where('t.user_id = :userId', { userId });

    if (query.organization_id) {
      qb.andWhere('t.organization_id = :orgId', { orgId: query.organization_id });
    }
    if (query.status) {
      qb.andWhere('t.status = :status', { status: query.status });
    }
    if (query.from_date) {
      qb.andWhere('t.end_date >= :fromDate', { fromDate: query.from_date });
    }
    if (query.to_date) {
      qb.andWhere('t.start_date <= :toDate', { toDate: query.to_date });
    }

    qb.orderBy('t.start_date', 'DESC')
      .skip((page - 1) * limit)
      .take(limit);

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(userId: string, id: string): Promise<TimeOffRequest> {
    const request = await this.timeOffRequestRepository.findOne({
      where: { id, user_id: userId },
    });
    if (!request) throw new NotFoundException('Time-off request not found');
    return request;
  }

  async cancel(userId: string, id: string): Promise<TimeOffRequest> {
    const request = await this.findOne(userId, id);
    if (request.status !== 'pending') {
      throw new BadRequestException('Only pending requests can be cancelled');
    }
    await this.timeOffRequestRepository.remove(request);
    return request;
  }
}
