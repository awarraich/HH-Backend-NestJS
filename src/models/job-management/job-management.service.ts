import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JobPosting } from './entities/job-posting.entity';
import { JobApplication } from './entities/job-application.entity';
import { CreateJobPostingDto } from './dto/create-job-posting.dto';
import { CreateJobApplicationDto } from './dto/create-job-application.dto';
import { UpdateJobPostingDto } from './dto/update-job-posting.dto';
import { QueryJobPostingDto } from './dto/query-job-posting.dto';

@Injectable()
export class JobManagementService {
  constructor(
    @InjectRepository(JobPosting)
    private jobPostingRepository: Repository<JobPosting>,
    @InjectRepository(JobApplication)
    private jobApplicationRepository: Repository<JobApplication>,
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

  /**
   * List all active job postings across organizations (public careers page).
   * Returns jobs with organization relation for display name.
   */
  async findAllActive(
    query: QueryJobPostingDto,
  ): Promise<{ data: JobPosting[]; total: number; page: number; limit: number }> {
    const page = query.page ?? 1;
    const limit = Math.min(query.limit ?? 20, 100);
    const skip = (page - 1) * limit;

    const qb = this.jobPostingRepository
      .createQueryBuilder('jp')
      .leftJoinAndSelect('jp.organization', 'org')
      .where('jp.status = :status', { status: 'active' })
      .orderBy('jp.created_at', 'DESC')
      .skip(skip)
      .take(limit);

    if (query.search?.trim()) {
      qb.andWhere(
        '(jp.title ILIKE :search OR jp.description ILIKE :search OR jp.location ILIKE :search)',
        { search: `%${query.search.trim()}%` },
      );
    }

    const [data, total] = await qb.getManyAndCount();
    return { data, total, page, limit };
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

  /**
   * Public: get one active job by id with organization (for apply page).
   * Returns 404 if not found or not active.
   */
  async findOneByIdPublic(id: string): Promise<JobPosting> {
    const job = await this.jobPostingRepository.findOne({
      where: { id, status: 'active' },
      relations: ['organization'],
    });
    if (!job) {
      throw new NotFoundException(`Job posting ${id} not found or not active`);
    }
    return job;
  }

  async update(organizationId: string, id: string, dto: UpdateJobPostingDto): Promise<JobPosting> {
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

  /**
   * Public: create a job application (apply form submit). Job must exist and be active.
   */
  async createApplication(dto: CreateJobApplicationDto): Promise<JobApplication> {
    const job = await this.jobPostingRepository.findOne({
      where: { id: dto.job_posting_id, status: 'active' },
    });
    if (!job) {
      throw new BadRequestException('Job posting not found or not accepting applications');
    }
    const submittedFields =
      dto.submitted_fields != null &&
      typeof dto.submitted_fields === 'object' &&
      !Array.isArray(dto.submitted_fields)
        ? dto.submitted_fields
        : null;
    const application = this.jobApplicationRepository.create({
      job_posting_id: dto.job_posting_id,
      applicant_name: String(dto.applicant_name).trim(),
      applicant_email: String(dto.applicant_email).trim(),
      applicant_phone: dto.applicant_phone ? String(dto.applicant_phone).trim() : null,
      notes: dto.notes != null ? String(dto.notes) : null,
      submitted_fields: submittedFields,
      status: 'pending',
    });
    try {
      return await this.jobApplicationRepository.save(application);
    } catch (err: unknown) {
      const ex = err as { message?: string; code?: string };
      const msg = ex?.message || String(err);
      if (ex?.code === '42P01' || (typeof msg === 'string' && msg.includes('does not exist'))) {
        throw new BadRequestException(
          'Database table job_applications may not exist. Run migrations or set DB_SYNCHRONIZE=true and restart.',
        );
      }
      throw err;
    }
  }

  /**
   * List applications for a job posting. Job must belong to the organization.
   */
  async findApplicationsByJobPosting(
    organizationId: string,
    jobId: string,
  ): Promise<JobApplication[]> {
    const job = await this.jobPostingRepository.findOne({
      where: { id: jobId, organization_id: organizationId },
    });
    if (!job) {
      throw new NotFoundException('Job posting not found');
    }
    const list = await this.jobApplicationRepository.find({
      where: { job_posting_id: jobId },
      order: { created_at: 'DESC' },
      relations: ['job_posting'],
    });
    return list;
  }

  /**
   * List all applications for an organization (across all job postings).
   */
  async findAllApplicationsByOrganization(organizationId: string): Promise<JobApplication[]> {
    return this.jobApplicationRepository
      .createQueryBuilder('ja')
      .leftJoinAndSelect('ja.job_posting', 'jp')
      .where('jp.organization_id = :organizationId', { organizationId })
      .orderBy('ja.created_at', 'DESC')
      .getMany();
  }
}
