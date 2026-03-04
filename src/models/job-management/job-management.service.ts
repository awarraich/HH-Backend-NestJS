import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { CreateJobPostingDto } from './dto/create-job-posting.dto';
import { UpdateJobPostingDto } from './dto/update-job-posting.dto';
import { QueryJobPostingDto } from './dto/query-job-posting.dto';

@Injectable()
export class JobManagementService {
  constructor(
    @InjectRepository(JobPosting)
    private jobPostingRepository: Repository<JobPosting>,
  ) {}

  async create(organizationId: string, dto: CreateJobPostingDto): Promise<JobPosting> {
    const applicationDeadline = dto.application_deadline
      ? new Date(dto.application_deadline)
      : null;

    const details: Record<string, unknown> = {
      expand_candidate_search: dto.expand_candidate_search,
      required_fields: dto.required_fields,
      optional_fields: dto.optional_fields,
      job_types: dto.job_types,
      expected_hours_type: dto.expected_hours_type,
      expected_hours_value: dto.expected_hours_value,
      pay_type: dto.pay_type,
      pay_minimum: dto.pay_minimum,
      pay_maximum: dto.pay_maximum,
      pay_rate: dto.pay_rate,
      benefits: dto.benefits,
      education_level: dto.education_level,
      licenses_certifications: dto.licenses_certifications,
      field_of_study: dto.field_of_study,
      experience: dto.experience,
      required_qualifications: dto.required_qualifications,
      preferred_qualifications: dto.preferred_qualifications,
      skills: dto.skills,
      communication_emails: dto.communication_emails,
      send_individual_emails: dto.send_individual_emails,
      resume_required: dto.resume_required,
      allow_candidate_contact: dto.allow_candidate_contact,
      criminal_record_encouraged: dto.criminal_record_encouraged,
      background_check_required: dto.background_check_required,
      hiring_timeline: dto.hiring_timeline,
      people_to_hire: dto.people_to_hire,
    };

    const entity = this.jobPostingRepository.create({
      organization_id: organizationId,
      title: dto.title,
      description: dto.description ?? null,
      location: dto.location ?? null,
      location_type: dto.location_type ?? 'in_person',
      salary_range: dto.salary_range ?? null,
      application_deadline: applicationDeadline,
      status: dto.status ?? 'active',
      details,
    });

    return this.jobPostingRepository.save(entity);
  }

  async findAllByOrganization(
    organizationId: string,
    query: QueryJobPostingDto,
  ): Promise<{ data: JobPosting[]; total: number; page: number; limit: number }> {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const qb = this.jobPostingRepository
      .createQueryBuilder('jp')
      .where('jp.organization_id = :organizationId', { organizationId })
      .orderBy('jp.created_at', 'DESC')
      .skip(skip)
      .take(limit);

    if (query.status) {
      qb.andWhere('jp.status = :status', { status: query.status });
    }
    if (query.search?.trim()) {
      qb.andWhere(
        '(jp.title ILIKE :search OR jp.description ILIKE :search OR jp.location ILIKE :search)',
        { search: `%${query.search.trim()}%` },
      );
    }

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
  }

  async findOne(organizationId: string, id: string): Promise<JobPosting> {
    const job = await this.jobPostingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!job) {
      throw new NotFoundException(`Job posting ${id} not found`);
    }
    return job;
  }

  async findOneById(id: string): Promise<JobPosting> {
    const job = await this.jobPostingRepository.findOne({ where: { id } });
    if (!job) {
      throw new NotFoundException(`Job posting ${id} not found`);
    }
    return job;
  }

  async update(
    organizationId: string,
    id: string,
    dto: UpdateJobPostingDto,
  ): Promise<JobPosting> {
    const job = await this.findOne(organizationId, id);
    if (dto.status !== undefined) {
      job.status = dto.status;
    }
    return this.jobPostingRepository.save(job);
  }

  async remove(organizationId: string, id: string): Promise<void> {
    const job = await this.findOne(organizationId, id);
    await this.jobPostingRepository.remove(job);
  }
}
