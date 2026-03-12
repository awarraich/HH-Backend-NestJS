import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { JobPosting } from '../entities/job-posting.entity';
import { JobApplication } from '../entities/job-application.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { CreateJobPostingDto } from '../dto/create-job-posting.dto';
import { CreateJobApplicationDto } from '../dto/create-job-application.dto';
import { UpdateJobApplicationDto } from '../dto/update-job-application.dto';
import { UpdateJobPostingDto } from '../dto/update-job-posting.dto';
import { QueryJobPostingDto } from '../dto/query-job-posting.dto';
import { SendInterviewInviteDto } from '../dto/send-interview-invite.dto';
import { SendOfferLetterDto } from '../dto/send-offer-letter.dto';
import { EmailService } from '../../../common/services/email/email.service';

@Injectable()
export class JobManagementService {
  constructor(
    @InjectRepository(JobPosting)
    private jobPostingRepository: Repository<JobPosting>,
    @InjectRepository(JobApplication)
    private jobApplicationRepository: Repository<JobApplication>,
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    private readonly emailService: EmailService,
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
      application_fields: dto.application_fields ?? undefined,
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
   * Fetches jobs without loading full Organization entity so the endpoint works even if
   * the organizations table is missing optional columns (e.g. application_form_fields).
   */
  async findAllActive(
    query: QueryJobPostingDto,
  ): Promise<{ data: JobPosting[]; total: number; page: number; limit: number }> {
    const page = query.page ?? 1;
    const limit = Math.min(query.limit ?? 20, 100);
    const skip = (page - 1) * limit;

    const qb = this.jobPostingRepository
      .createQueryBuilder('jp')
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

    if (data.length > 0) {
      const orgIds = [...new Set(data.map((j) => j.organization_id).filter(Boolean))];
      const orgs = await this.organizationRepository.find({
        where: { id: In(orgIds) },
        select: ['id', 'organization_name'],
      });
      const orgMap = new Map(orgs.map((o) => [o.id, o]));
      type JobWithOrg = Omit<JobPosting, 'organization'> & {
        organization: Pick<Organization, 'id' | 'organization_name'> | null;
      };
      for (const job of data) {
        const org: Pick<Organization, 'id' | 'organization_name'> | null = job.organization_id
          ? (orgMap.get(job.organization_id) ?? null)
          : null;
        (job as JobWithOrg).organization = org;
      }
    }

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

    if (dto.title !== undefined) job.title = dto.title;
    if (dto.description !== undefined) job.description = dto.description ?? null;
    if (dto.location !== undefined) job.location = dto.location ?? null;
    if (dto.location_type !== undefined) job.location_type = dto.location_type ?? 'in_person';
    if (dto.salary_range !== undefined) job.salary_range = dto.salary_range ?? null;
    if (dto.application_deadline !== undefined) {
      job.application_deadline = dto.application_deadline
        ? new Date(dto.application_deadline)
        : null;
    }
    if (dto.status !== undefined) job.status = dto.status;

    const details: Record<string, unknown> = {
      ...((job.details as Record<string, unknown>) || {}),
    };
    if (dto.expand_candidate_search !== undefined)
      details.expand_candidate_search = dto.expand_candidate_search;
    if (dto.required_fields !== undefined) details.required_fields = dto.required_fields;
    if (dto.optional_fields !== undefined) details.optional_fields = dto.optional_fields;
    if (dto.job_types !== undefined) details.job_types = dto.job_types;
    if (dto.expected_hours_type !== undefined)
      details.expected_hours_type = dto.expected_hours_type;
    if (dto.expected_hours_value !== undefined)
      details.expected_hours_value = dto.expected_hours_value;
    if (dto.pay_type !== undefined) details.pay_type = dto.pay_type;
    if (dto.pay_minimum !== undefined) details.pay_minimum = dto.pay_minimum;
    if (dto.pay_maximum !== undefined) details.pay_maximum = dto.pay_maximum;
    if (dto.pay_rate !== undefined) details.pay_rate = dto.pay_rate;
    if (dto.benefits !== undefined) details.benefits = dto.benefits;
    if (dto.education_level !== undefined) details.education_level = dto.education_level;
    if (dto.licenses_certifications !== undefined)
      details.licenses_certifications = dto.licenses_certifications;
    if (dto.field_of_study !== undefined) details.field_of_study = dto.field_of_study;
    if (dto.experience !== undefined) details.experience = dto.experience;
    if (dto.required_qualifications !== undefined)
      details.required_qualifications = dto.required_qualifications;
    if (dto.preferred_qualifications !== undefined)
      details.preferred_qualifications = dto.preferred_qualifications;
    if (dto.skills !== undefined) details.skills = dto.skills;
    if (dto.communication_emails !== undefined)
      details.communication_emails = dto.communication_emails;
    if (dto.send_individual_emails !== undefined)
      details.send_individual_emails = dto.send_individual_emails;
    if (dto.resume_required !== undefined) details.resume_required = dto.resume_required;
    if (dto.allow_candidate_contact !== undefined)
      details.allow_candidate_contact = dto.allow_candidate_contact;
    if (dto.criminal_record_encouraged !== undefined)
      details.criminal_record_encouraged = dto.criminal_record_encouraged;
    if (dto.background_check_required !== undefined)
      details.background_check_required = dto.background_check_required;
    if (dto.hiring_timeline !== undefined) details.hiring_timeline = dto.hiring_timeline;
    if (dto.people_to_hire !== undefined) details.people_to_hire = dto.people_to_hire;
    if (dto.application_fields !== undefined) details.application_fields = dto.application_fields;

    job.details = details;
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

  /**
   * Update a job application (e.g. status). Application must belong to a job posting of the organization.
   */
  async updateApplicationStatus(
    organizationId: string,
    applicationId: string,
    dto: UpdateJobApplicationDto,
  ): Promise<JobApplication> {
    const application = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
      relations: ['job_posting'],
    });
    if (!application) {
      throw new NotFoundException(`Job application ${applicationId} not found`);
    }
    if (application.job_posting?.organization_id !== organizationId) {
      throw new NotFoundException(
        `Job application ${applicationId} not found for this organization`,
      );
    }
    if (dto.status !== undefined) {
      application.status = dto.status;
    }
    return this.jobApplicationRepository.save(application);
  }

  /**
   * Send interview invite email to applicant. Application must belong to the organization.
   * Fails with 400 if email service is not configured (e.g. missing EMAIL_USER/EMAIL_PASSWORD in production).
   */
  async sendInterviewInviteEmail(
    organizationId: string,
    applicationId: string,
    dto: SendInterviewInviteDto,
  ): Promise<{ message: string }> {
    const application = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
      relations: ['job_posting'],
    });
    if (!application) {
      throw new NotFoundException(`Job application ${applicationId} not found`);
    }
    if (application.job_posting?.organization_id !== organizationId) {
      throw new NotFoundException(
        `Job application ${applicationId} not found for this organization`,
      );
    }
    try {
      await this.emailService.sendInterviewInviteEmail(
        dto.toEmail,
        dto.applicantName,
        dto.jobTitle,
        dto.interviewDate,
        dto.interviewTime,
        dto.message,
      );
      return { message: 'Interview invite email sent successfully' };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('not configured')) {
        throw new BadRequestException(
          'Email is not configured. Set EMAIL_USER and EMAIL_PASSWORD in your environment to send interview invites.',
        );
      }
      throw new BadRequestException(`Failed to send interview invite email: ${msg}`);
    }
  }

  /**
   * Send offer letter email to applicant. Application must belong to the organization.
   * Fails with 400 if email service is not configured.
   */
  async sendOfferLetterEmail(
    organizationId: string,
    applicationId: string,
    dto: SendOfferLetterDto,
  ): Promise<{ message: string }> {
    const application = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
      relations: ['job_posting'],
    });
    if (!application) {
      throw new NotFoundException(`Job application ${applicationId} not found`);
    }
    if (application.job_posting?.organization_id !== organizationId) {
      throw new NotFoundException(
        `Job application ${applicationId} not found for this organization`,
      );
    }
    try {
      await this.emailService.sendOfferLetterEmail(
        dto.toEmail,
        dto.applicantName,
        dto.jobTitle,
        dto.salary,
        dto.startDate,
        dto.offerContent,
        dto.attachmentUrl,
      );
      return { message: 'Offer letter email sent successfully' };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('not configured')) {
        throw new BadRequestException(
          'Email is not configured. Set EMAIL_USER and EMAIL_PASSWORD in your environment to send offer letters.',
        );
      }
      throw new BadRequestException(`Failed to send offer letter email: ${msg}`);
    }
  }

  /**
   * Public: get merged application form for a job (org fields + job-specific fields).
   * Used by apply page so all fields from application setup and job posting are returned in one call.
   */
  async getApplicationFormForJob(jobId: string): Promise<{
    required: Record<string, unknown>[];
    optional: Record<string, unknown>[];
  }> {
    const job = await this.findOneByIdPublic(jobId);
    const details = (job.details as Record<string, unknown>) ?? {};
    const orgFields = await this.getApplicationFormFields(job.organization_id);
    const reqIds = new Set(
      (Array.isArray(details.required_fields) ? details.required_fields : []).map((r: unknown) =>
        typeof r === 'string' ? r : ((r as { id?: string })?.id ?? ''),
      ),
    );
    const optIds = new Set(
      (Array.isArray(details.optional_fields) ? details.optional_fields : []).map((o: unknown) =>
        typeof o === 'string' ? o : ((o as { id?: string })?.id ?? ''),
      ),
    );
    const toField = (f: Record<string, unknown>): Record<string, unknown> => {
      const id = typeof f.id === 'string' ? f.id : '';
      return {
        id,
        name: typeof f.name === 'string' ? f.name : id,
        display_name:
          typeof f.display_name === 'string'
            ? f.display_name
            : typeof f.label === 'string'
              ? f.label
              : '',
        field_type:
          typeof f.field_type === 'string'
            ? f.field_type
            : typeof f.type === 'string'
              ? f.type
              : 'text',
        description:
          typeof f.description === 'string'
            ? f.description
            : typeof f.placeholder === 'string'
              ? f.placeholder
              : '',
        options: f.options,
      };
    };
    const idStr = (f: Record<string, unknown>): string => (typeof f.id === 'string' ? f.id : '');
    let required: Record<string, unknown>[] = [];
    let optional: Record<string, unknown>[] = [];
    if (orgFields.length > 0) {
      if (reqIds.size > 0 || optIds.size > 0) {
        required = orgFields.filter((f) => reqIds.has(idStr(f))).map(toField);
        optional = orgFields.filter((f) => optIds.has(idStr(f))).map(toField);
        const rest = orgFields
          .filter((f) => !reqIds.has(idStr(f)) && !optIds.has(idStr(f)))
          .map(toField);
        optional = [...optional, ...rest];
      } else {
        required = orgFields
          .filter((f) => (f as { required?: boolean }).required === true)
          .map(toField);
        optional = orgFields.filter((f) => !(f as { required?: boolean }).required).map(toField);
      }
    }
    const jobFields = (
      Array.isArray(details.application_fields) ? details.application_fields : []
    ) as Record<string, unknown>[];
    for (const f of jobFields) {
      const field = toField(f);
      const isReq = (f as { required?: boolean }).required !== false;
      if (isReq) required.push(field);
      else optional.push(field);
    }
    return { required, optional };
  }

  /**
   * Get organization's job application form field definitions.
   * Public so apply form can load fields without auth.
   */
  async getApplicationFormFields(organizationId: string): Promise<Record<string, unknown>[]> {
    const org = await this.organizationRepository.findOne({
      where: { id: organizationId },
      select: ['id', 'application_form_fields'],
    });
    if (!org) return [];
    const raw = org.application_form_fields;
    return (Array.isArray(raw) ? raw : []) as Record<string, unknown>[];
  }

  /**
   * Set organization's job application form field definitions.
   * Called from Application Form Setup (org admin).
   */
  async setApplicationFormFields(
    organizationId: string,
    fields: Record<string, unknown>[],
  ): Promise<Record<string, unknown>[]> {
    const org = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!org) {
      throw new NotFoundException(`Organization ${organizationId} not found`);
    }
    const normalized = Array.isArray(fields) ? fields : [];
    await this.organizationRepository.update(organizationId, {
      application_form_fields: normalized as object[],
    });
    return normalized;
  }
}
