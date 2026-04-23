import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository, In } from 'typeorm';
import type { QueryDeepPartialEntity } from 'typeorm/query-builder/QueryPartialEntity';
import { JobPosting } from '../entities/job-posting.entity';
import { JobApplication } from '../entities/job-application.entity';
import { JobApplicationFieldValue } from '../entities/job-application-field-value.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { OrganizationCompanyProfileService } from '../../organizations/company-profile-setup/services/organization-company-profile.service';
import { Employee } from '../../employees/entities/employee.entity';
import { EmployeeProfile } from '../../employees/entities/employee-profile.entity';
import { User } from '../../../authentication/entities/user.entity';
import { CreateJobPostingDto } from '../dto/create-job-posting.dto';
import { CreateJobApplicationDto } from '../dto/create-job-application.dto';
import { UpdateJobApplicationDto } from '../dto/update-job-application.dto';
import { UpdateJobPostingDto } from '../dto/update-job-posting.dto';
import { QueryJobPostingDto } from '../dto/query-job-posting.dto';
import { QueryJobApplicationsDto } from '../dto/query-job-applications.dto';
import { SendInterviewInviteDto } from '../dto/send-interview-invite.dto';
import { EmailService } from '../../../common/services/email/email.service';

@Injectable()
export class JobManagementService {
  constructor(
    @InjectRepository(JobPosting)
    private jobPostingRepository: Repository<JobPosting>,
    @InjectRepository(JobApplication)
    private jobApplicationRepository: Repository<JobApplication>,
    @InjectRepository(JobApplicationFieldValue)
    private jobApplicationFieldValueRepository: Repository<JobApplicationFieldValue>,
    @InjectRepository(Organization)
    private organizationRepository: Repository<Organization>,
    @InjectRepository(Employee)
    private employeeRepository: Repository<Employee>,
    @InjectRepository(EmployeeProfile)
    private employeeProfileRepository: Repository<EmployeeProfile>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private readonly emailService: EmailService,
    private readonly companyProfileService: OrganizationCompanyProfileService,
    private readonly dataSource: DataSource,
  ) {}

  private async resolveOrganizationName(
    organizationId: string,
  ): Promise<string | undefined> {
    const org = await this.organizationRepository.findOne({
      where: { id: organizationId },
      select: ['id', 'organization_name'],
    });
    return org?.organization_name?.trim() || undefined;
  }

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
      // Snapshot the application form at create time so later changes to the
      // org-level setup don't retroactively alter this posting's form.
      application_fields_snapshot:
        Array.isArray(dto.application_fields_snapshot) && dto.application_fields_snapshot.length > 0
          ? dto.application_fields_snapshot
          : null,
    });

    return this.jobPostingRepository.save(entity);
  }

  /**
   * List all active job postings across organizations (public careers page).
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
   * Public: get one active job by id with organization.
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

    // Per-job snapshot of the application form (independent of org setup).
    // Accept an empty array as an explicit "no fields" state; callers can send
    // null to fall back to the legacy org-setup path.
    if (dto.application_fields_snapshot !== undefined) {
      job.application_fields_snapshot = Array.isArray(dto.application_fields_snapshot)
        ? dto.application_fields_snapshot
        : null;
    }

    job.details = details;
    return this.jobPostingRepository.save(job);
  }

  async remove(organizationId: string, id: string): Promise<void> {
    const job = await this.findOne(organizationId, id);
    await this.jobPostingRepository.remove(job);
  }

  /**
   * Public: create a job application (apply form submit). Job must exist and be active.
   * `authUserId` is the caller's user id when a valid JWT was present; null
   * for guest applies. When set it's persisted on `applicant_user_id`, giving
   * the Send Offer flow a durable link to the candidate's account.
   */
  async createApplication(
    dto: CreateJobApplicationDto,
    authUserId: string | null = null,
  ): Promise<JobApplication> {
    const job = await this.jobPostingRepository.findOne({
      where: { id: dto.job_posting_id, status: 'active' },
    });
    if (!job) {
      throw new BadRequestException('Job posting not found.');
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
      applicant_user_id: authUserId,
      applicant_phone: dto.applicant_phone ? String(dto.applicant_phone).trim() : null,
      notes: dto.notes != null ? String(dto.notes) : null,
      // Keep populating the legacy JSONB column during the transition so older reads still work.
      submitted_fields: submittedFields,
      status: 'pending',
    });
    try {
      const saved = await this.jobApplicationRepository.save(application);
      // Fan out each form answer into its own row in the normalized table.
      const rows = this.buildFieldValueRows(saved.id, submittedFields);
      if (rows.length > 0) {
        await this.jobApplicationFieldValueRepository
          .createQueryBuilder()
          .insert()
          .values(rows as unknown as QueryDeepPartialEntity<JobApplicationFieldValue>[])
          .orIgnore()
          .execute();
      }
      return saved;
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
   * Paginated list of applications for an organization (across all job postings).
   *
   * Supports:
   *   - `status` — concrete state OR the bucket `offers` (any offer-lifecycle state)
   *   - `q` — case-insensitive search on applicant name/email and job title
   *   - `job_posting_id` — filter to a single job
   *   - `page` / `limit` — standard paging
   *
   * Returns a pagination envelope with `total_by_status` so the UI can render tab badges
   * without loading every row.
   */
  async findAllApplicationsByOrganization(
    organizationId: string,
    query: QueryJobApplicationsDto = {},
  ): Promise<{
    applications: JobApplication[];
    page: number;
    limit: number;
    total: number;
    has_more: boolean;
    total_by_status: Record<string, number>;
  }> {
    const page = Math.max(1, query.page ?? 1);
    const limit = Math.min(100, Math.max(1, query.limit ?? 25));

    const base = this.jobApplicationRepository
      .createQueryBuilder('ja')
      .leftJoinAndSelect('ja.job_posting', 'jp')
      .leftJoinAndSelect('ja.field_values', 'fv')
      .where('jp.organization_id = :organizationId', { organizationId });

    // Optional: single job filter
    if (query.job_posting_id) {
      base.andWhere('ja.job_posting_id = :jobPostingId', {
        jobPostingId: query.job_posting_id,
      });
    }

    // Optional: text search across applicant fields + job title
    if (query.q && query.q.trim()) {
      const needle = `%${query.q.trim().toLowerCase()}%`;
      base.andWhere(
        '(LOWER(ja.applicant_name) LIKE :q OR LOWER(ja.applicant_email) LIKE :q OR LOWER(jp.title) LIKE :q)',
        { q: needle },
      );
    }

    // Status filter — supports the special "offers" bucket which maps to any
    // offer state. Former employees (status=terminated) live in their own
    // tab and are excluded from the "all" view so HR isn't greeted by a
    // list full of ex-staff; filtering explicitly by `status=terminated`
    // still returns them.
    // `offer_pending` (internal signers still working) and `offer_signed`
    // (internals done, awaiting applicant response) count as offer-lifecycle
    // rows too — leaving them out hides freshly-sent offers from the Offer
    // Letters tab while HR waits for signatures to wrap.
    const OFFER_STATES = [
      'offer_sent',
      'offer_pending',
      'offer_signed',
      'offer_accepted',
      'offer_declined',
    ];
    if (query.status && query.status !== 'all') {
      if (query.status === 'offers') {
        base.andWhere('ja.status IN (:...offerStates)', { offerStates: OFFER_STATES });
      } else {
        base.andWhere('ja.status = :status', { status: query.status });
      }
    } else {
      base.andWhere('ja.status <> :terminatedStatus', {
        terminatedStatus: 'terminated',
      });
    }

    // Compute the paginated slice + total in one round-trip
    const [applications, total] = await base
      .orderBy('ja.created_at', 'DESC')
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();

    // Re-hydrate legacy `submitted_fields` from the normalized rows so any consumer still
    // reading that shape keeps working. When all consumers have migrated we can drop this
    // projection and the `submitted_fields` column in a follow-up.
    for (const app of applications) {
      const projected = this.projectFieldValuesToSubmittedFields(app.field_values);
      if (projected) app.submitted_fields = projected;
    }

    // Ensure every row surfaces an `applicant_user_id` for the Send Offer
    // flow. The column is populated at apply time when a JWT is present and
    // by the migration backfill for historical rows; anything still null here
    // means the applicant genuinely has no matching user account yet (guest
    // apply + never signed up). We still attempt one more email → User match
    // as a cheap defensive fallback in case a user signed up after applying.
    const unlinked = applications.filter((a) => !a.applicant_user_id);
    if (unlinked.length > 0) {
      const emails = Array.from(
        new Set(
          unlinked
            .map((a) => a.applicant_email?.trim().toLowerCase())
            .filter((e): e is string => !!e),
        ),
      );
      if (emails.length > 0) {
        const users = await this.userRepository
          .createQueryBuilder('u')
          .where('LOWER(u.email) IN (:...emails)', { emails })
          .select(['u.id', 'u.email'])
          .getMany();
        const userIdByEmail = new Map<string, string>();
        for (const u of users) {
          if (u.email) userIdByEmail.set(u.email.toLowerCase(), u.id);
        }
        for (const app of unlinked) {
          const email = app.applicant_email?.trim().toLowerCase();
          if (email) app.applicant_user_id = userIdByEmail.get(email) ?? null;
        }
      }
    }

    // Unfiltered-by-status counts (still scoped to the same org / job / search context)
    // so tab badges show exact numbers independent of the current tab selection.
    const breakdownBase = this.jobApplicationRepository
      .createQueryBuilder('ja')
      .leftJoin('ja.job_posting', 'jp')
      .where('jp.organization_id = :organizationId', { organizationId });
    if (query.job_posting_id) {
      breakdownBase.andWhere('ja.job_posting_id = :jobPostingId', {
        jobPostingId: query.job_posting_id,
      });
    }
    if (query.q && query.q.trim()) {
      const needle = `%${query.q.trim().toLowerCase()}%`;
      breakdownBase.andWhere(
        '(LOWER(ja.applicant_name) LIKE :q OR LOWER(ja.applicant_email) LIKE :q OR LOWER(jp.title) LIKE :q)',
        { q: needle },
      );
    }
    const rawCounts: Array<{ status: string; count: string }> = await breakdownBase
      .select('ja.status', 'status')
      .addSelect('COUNT(ja.id)', 'count')
      .groupBy('ja.status')
      .getRawMany();
    const totalByStatus: Record<string, number> = {
      all: 0,
      not_seen: 0,
      interview: 0,
      offer_sent: 0,
      offer_accepted: 0,
      offer_declined: 0,
      rejected: 0,
      hired: 0,
      terminated: 0,
      offers: 0,
    };
    for (const row of rawCounts) {
      const n = Number(row.count) || 0;
      const normalized = this.normalizeStatusKey(row.status);
      totalByStatus[normalized] = (totalByStatus[normalized] ?? 0) + n;
      // `all` mirrors the list endpoint — former employees live in their own
      // bucket and don't inflate the active pipeline count.
      if (normalized !== 'terminated') totalByStatus.all += n;
      if (OFFER_STATES.includes(normalized)) totalByStatus.offers += n;
    }

    return {
      applications,
      page,
      limit,
      total,
      has_more: page * limit < total,
      total_by_status: totalByStatus,
    };
  }

  /**
   * Explode a `submitted_fields` JSONB blob into one `JobApplicationFieldValue` per top-level key.
   * Plain strings go into `value_text`; every other shape goes into `value_json`.
   * Empty / null values are skipped.
   */
  private buildFieldValueRows(
    applicationId: string,
    submittedFields: Record<string, unknown> | null | undefined,
  ): Partial<JobApplicationFieldValue>[] {
    if (!submittedFields || typeof submittedFields !== 'object' || Array.isArray(submittedFields)) {
      return [];
    }
    const rows: Partial<JobApplicationFieldValue>[] = [];
    for (const [key, raw] of Object.entries(submittedFields)) {
      if (raw == null) continue;
      if (typeof raw === 'string') {
        if (raw.length === 0) continue;
        rows.push({ application_id: applicationId, field_key: key, value_text: raw, value_json: null });
      } else {
        rows.push({ application_id: applicationId, field_key: key, value_text: null, value_json: raw });
      }
    }
    return rows;
  }

  /**
   * Re-assemble the legacy `submitted_fields` map from normalized rows so existing
   * frontend consumers (that still read `submitted_fields`) keep working during the transition.
   */
  private projectFieldValuesToSubmittedFields(
    values: JobApplicationFieldValue[] | undefined | null,
  ): Record<string, unknown> | null {
    if (!values || values.length === 0) return null;
    const out: Record<string, unknown> = {};
    for (const v of values) {
      if (v.value_text !== null && v.value_text !== undefined) {
        out[v.field_key] = v.value_text;
      } else if (v.value_json !== null && v.value_json !== undefined) {
        out[v.field_key] = v.value_json;
      }
    }
    return out;
  }

  /** Collapse raw status strings into the normalized bucket keys the frontend uses. */
  private normalizeStatusKey(raw: string | null | undefined): string {
    const s = (raw ?? 'pending').toString().toLowerCase().trim().replace(/\s+/g, '_');
    if (s === 'rejected') return 'rejected';
    if (s === 'interview' || s === 'interview_scheduled') return 'interview';
    if (s === 'offer_sent' || s === 'offer') return 'offer_sent';
    if (s === 'offer_accepted') return 'offer_accepted';
    if (s === 'offer_declined') return 'offer_declined';
    if (s === 'offer_pending') return 'offer_pending';
    if (s === 'offer_signed') return 'offer_signed';
    if (s === 'hired') return 'hired';
    if (s === 'terminated') return 'terminated';
    return 'not_seen';
  }

  /**
   * Employee "My Applications" endpoint helper.
   */
  async findMyJobApplicationsByUserId(userId: string): Promise<
    Array<{
      id: string;
      job_posting_id: string;
      status: string;
      applicant_name: string;
      created_at: Date;
      offer_details?: Record<string, unknown> | null;
      interview_details?: Record<string, unknown> | null;
      decline_reason?: string | null;
      job_posting?: { id: string; title: string };
      organization?: { id: string; organization_name: string };
    }>
  > {
    if (!userId) return [];

    // Look up the email from the users table directly so this endpoint also
    // works for applicants — users who have signed up and applied to jobs but
    // have not yet been hired into any organization (no employees row exists).
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const email = user?.email;
    if (!email) return [];

    const applications = await this.jobApplicationRepository
      .createQueryBuilder('ja')
      .leftJoinAndSelect('ja.job_posting', 'jp')
      .leftJoinAndSelect('jp.organization', 'org')
      .where('ja.applicant_email = :email', { email })
      .orderBy('ja.created_at', 'DESC')
      .getMany();

    return applications.map((ja) => ({
      id: ja.id,
      job_posting_id: ja.job_posting_id,
      status: ja.status,
      applicant_name: ja.applicant_name,
      created_at: ja.created_at,
      offer_details: ja.offer_details ?? null,
      interview_details: ja.interview_details ?? null,
      decline_reason: ja.decline_reason ?? null,
      ...(ja.job_posting
        ? { job_posting: { id: ja.job_posting.id, title: ja.job_posting.title } }
        : {}),
      ...(ja.job_posting?.organization
        ? {
            organization: {
              id: ja.job_posting.organization.id,
              organization_name: ja.job_posting.organization.organization_name,
            },
          }
        : {}),
    }));
  }

  /**
   * Applicant-self detail view: fetch one of the caller's own job applications.
   * Authorization = email match between the authenticated user and the application.
   */
  async findMyJobApplicationByIdForUser(
    userId: string,
    applicationId: string,
  ): Promise<Record<string, unknown>> {
    if (!userId) {
      throw new NotFoundException('User not found');
    }
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const email = user?.email;
    if (!email) {
      throw new NotFoundException('User not found');
    }

    const ja = await this.jobApplicationRepository
      .createQueryBuilder('ja')
      .leftJoinAndSelect('ja.job_posting', 'jp')
      .leftJoinAndSelect('jp.organization', 'org')
      .where('ja.id = :applicationId', { applicationId })
      .andWhere('ja.applicant_email = :email', { email })
      .getOne();

    if (!ja) {
      throw new NotFoundException(
        `Job application ${applicationId} not found`,
      );
    }

    const offerDetails = (ja.offer_details ?? {}) as Record<string, unknown>;
    // Lift signing-flow URLs to top-level for frontend compatibility.
    return {
      id: ja.id,
      job_posting_id: ja.job_posting_id,
      status: ja.status,
      applicant_name: ja.applicant_name,
      applicant_email: ja.applicant_email,
      applicant_phone: ja.applicant_phone ?? null,
      submitted_fields: ja.submitted_fields ?? null,
      offer_details: offerDetails,
      decline_reason: ja.decline_reason ?? null,
      created_at: ja.created_at,
      offer_letter_url: offerDetails.offer_letter_url ?? null,
      application_form_url: offerDetails.application_form_url ?? null,
      filled_offer_letter_url: offerDetails.filled_offer_letter_url ?? null,
      filled_application_form_url:
        offerDetails.filled_application_form_url ?? null,
      ...(ja.job_posting
        ? { job_posting: { id: ja.job_posting.id, title: ja.job_posting.title } }
        : {}),
      ...(ja.job_posting?.organization
        ? {
            organization: {
              id: ja.job_posting.organization.id,
              organization_name: ja.job_posting.organization.organization_name,
            },
          }
        : {}),
    };
  }

  /**
   * Allowed status transitions. Kept explicit so "mark rejected" or
   * "accidentally set back to pending" can't nuke a live offer's state.
   * Each key is a current status; each value is the set of statuses HR is
   * allowed to move to from there. The candidate-side endpoint
   * (acceptOfferAsCandidate) has its own narrower rules below.
   */
  private static readonly STATUS_TRANSITIONS: Readonly<Record<string, readonly string[]>> = {
    // Offer can only be sent after an interview has been scheduled — HR must
    // move the candidate through `interview` first. Direct pending→offer
    // shortcuts are blocked so the audit trail always shows an interview step.
    pending: ['interview', 'rejected'],
    not_seen: ['interview', 'rejected'],
    interview: ['offer_sent', 'offer_pending', 'rejected', 'pending'],
    offer_sent: ['offer_pending', 'offer_accepted', 'offer_declined', 'rejected'],
    offer_pending: ['offer_sent', 'offer_signed', 'offer_accepted', 'offer_declined', 'rejected'],
    offer_signed: ['offer_accepted', 'offer_declined', 'rejected'],
    // From offer_accepted HR can move the candidate to `hired` (close the
    // loop by creating an Employee record) via the dedicated hire endpoint.
    offer_accepted: ['hired'],
    offer_declined: ['pending'],
    rejected: ['pending'],
    // When the Employee row is later deleted, the delete-employee flow
    // flips the linked application from `hired` to `terminated` so the
    // applications list stops showing a stale Hired badge.
    hired: ['terminated'],
    terminated: [],
  };

  /**
   * Update a job application (status, interview_details, offer_details).
   * Application must belong to a job posting of the organization. Status
   * transitions are validated against the STATUS_TRANSITIONS table above.
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
    if (dto.status !== undefined && dto.status !== application.status) {
      const current = (application.status ?? 'pending').toLowerCase();
      const next = String(dto.status).toLowerCase();
      const allowed = JobManagementService.STATUS_TRANSITIONS[current] ?? [];
      if (!allowed.includes(next)) {
        throw new BadRequestException(
          `Cannot change application status from "${current}" to "${next}".`,
        );
      }
      application.status = next;

      // Stamp the first time the app enters each milestone — power the
      // activity timeline. `?? new Date()` preserves original stamps on
      // status bounces (e.g. reject → reinstate → reject again keeps the
      // original rejection time unless we explicitly reset on reinstate).
      const now = new Date();
      if (next === 'interview') {
        application.interview_scheduled_at =
          application.interview_scheduled_at ?? now;
      } else if (next === 'offer_sent') {
        application.offer_sent_at = application.offer_sent_at ?? now;
      } else if (next === 'offer_accepted') {
        application.offer_accepted_at = application.offer_accepted_at ?? now;
      } else if (next === 'offer_declined') {
        application.offer_declined_at = application.offer_declined_at ?? now;
      } else if (next === 'rejected') {
        application.rejected_at = now; // refresh on each reject so the
        // timeline shows the latest decision
      } else if (next === 'hired') {
        application.hired_at = application.hired_at ?? now;
      } else if (next === 'pending' || next === 'not_seen') {
        // Reinstatement clears the rejection stamp so the timeline doesn't
        // lie about terminal state.
        application.rejected_at = null;
      }
    }
    if (dto.interview_details !== undefined) {
      // Full replace — the frontend sends the complete snapshot on schedule.
      application.interview_details = dto.interview_details;
    }
    if (dto.offer_details !== undefined) {
      // Merge so fields added later (e.g. signed_pdf_url after the candidate signs)
      // aren't wiped by a subsequent HR update.
      application.offer_details = {
        ...(application.offer_details ?? {}),
        ...dto.offer_details,
      };
    }
    if (dto.hr_notes !== undefined) {
      application.hr_notes = dto.hr_notes == null ? null : String(dto.hr_notes);
    }
    return this.jobApplicationRepository.save(application);
  }

  /**
   * Candidate accepts or declines the offer on their own application.
   *
   * Two things worth highlighting:
   *   1. **Ownership**: we verify via `applicant_user_id` when set (durable
   *      link from the apply-time JWT); otherwise we fall back to matching
   *      the auth'd user's email against `applicant_email` so guest-applies
   *      that later signed up still work.
   *   2. **Race-safe state change**: concurrent requests (double-click,
   *      browser retry) could both read `offer_sent` and both write. We use
   *      a conditional UPDATE that only transitions from an allowed "active
   *      offer" status, check `affected === 1`, and bail out loudly when
   *      the row has already moved on.
   */
  async acceptOfferAsCandidate(
    userId: string,
    applicationId: string,
    decision: 'accept' | 'decline',
    declineReason?: string | null,
  ): Promise<JobApplication> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const email = user?.email;
    if (!email) {
      throw new NotFoundException('User email not found');
    }
    const application = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
    });
    if (!application) {
      throw new NotFoundException(`Job application not found`);
    }
    const owns =
      (application.applicant_user_id &&
        application.applicant_user_id === userId) ||
      application.applicant_email?.toLowerCase() === email.toLowerCase();
    if (!owns) {
      throw new NotFoundException(`Job application not found`);
    }
    // Sequential-signing gate: `offer_pending` means internal signers (HR /
    // supervisor) haven't finished. Applicant can't accept yet — the
    // backend flips to `offer_sent` automatically once the last internal
    // signature lands. We surface a clear error instead of the generic
    // "no active offer" so the UI (and curl) knows exactly what's wrong.
    if (application.status === 'offer_pending') {
      throw new BadRequestException(
        'This offer is still being finalized by the organization. You will be notified once it is ready for your response.',
      );
    }
    const ACTIVE_OFFER_STATUSES = ['offer_sent', 'offer_signed'];
    if (!ACTIVE_OFFER_STATUSES.includes(application.status)) {
      throw new BadRequestException('No active offer to act on for this application');
    }
    const nextStatus = decision === 'accept' ? 'offer_accepted' : 'offer_declined';
    const trimmedReason =
      decision === 'decline'
        ? (declineReason?.toString().trim() ?? '')
        : '';
    // Atomic conditional write: only succeeds if the row is still in an
    // active-offer state. If a concurrent decision already happened, the
    // update affects 0 rows and we surface a conflict error instead of
    // silently overwriting the other decision.
    const result = await this.jobApplicationRepository
      .createQueryBuilder()
      .update(JobApplication)
      .set({
        status: nextStatus,
        decline_reason:
          decision === 'decline'
            ? trimmedReason.length > 0
              ? trimmedReason
              : null
            : null,
      })
      .where('id = :id', { id: applicationId })
      .andWhere('status IN (:...active)', { active: ACTIVE_OFFER_STATUSES })
      .execute();
    if ((result.affected ?? 0) === 0) {
      throw new BadRequestException(
        'This offer has already been acted on — refresh the page to see the current state.',
      );
    }
    const fresh = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
    });
    if (!fresh) {
      throw new NotFoundException('Job application not found');
    }
    return fresh;
  }

  /**
   * Applicant-self response to a scheduled interview. Writes an
   * `applicantResponse` block into `interview_details` so the org-facing
   * list sees whether the candidate confirmed or flagged a conflict (and
   * the free-text availability they offered). Does not change the
   * application status — HR still owns the scheduling workflow.
   */
  async respondToInterviewAsCandidate(
    userId: string,
    applicationId: string,
    response: 'confirmed' | 'unavailable',
    availability?: string | null,
  ): Promise<JobApplication> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const email = user?.email;
    if (!email) {
      throw new NotFoundException('User email not found');
    }
    const application = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
    });
    if (!application) {
      throw new NotFoundException('Job application not found');
    }
    const owns =
      (application.applicant_user_id &&
        application.applicant_user_id === userId) ||
      application.applicant_email?.toLowerCase() === email.toLowerCase();
    if (!owns) {
      throw new NotFoundException('Job application not found');
    }
    if ((application.status ?? '').toLowerCase() !== 'interview') {
      throw new BadRequestException(
        'No scheduled interview to respond to for this application.',
      );
    }
    const existing =
      application.interview_details &&
      typeof application.interview_details === 'object'
        ? (application.interview_details as Record<string, unknown>)
        : {};
    const trimmedAvailability =
      typeof availability === 'string' ? availability.trim() : '';
    const nextInterviewDetails: Record<string, unknown> = {
      ...existing,
      applicantResponse: {
        status: response,
        ...(trimmedAvailability.length > 0
          ? { availability: trimmedAvailability }
          : {}),
        respondedAt: new Date().toISOString(),
      },
    };
    application.interview_details = nextInterviewDetails;
    await this.jobApplicationRepository.save(application);
    return application;
  }

  /**
   * HR-triggered hire. Creates an Employee row for the applicant and
   * transitions the application to `hired`. Idempotent: calling again
   * after the application is already `hired` is a no-op that returns the
   * existing employee. Gated by:
   *   1. Application must belong to `organizationId`.
   *   2. Application status must be `offer_accepted` (or already `hired` for idempotency).
   *   3. Internal signing must be complete (offer_details.internalSigningComplete === true
   *      OR no internal signers were ever required — flag absent).
   *   4. Applicant must have a resolved `applicant_user_id`.
   */
  async hireApplicant(
    organizationId: string,
    applicationId: string,
    overrides?: {
      employmentType?: string | null;
      startDate?: string | null;
      department?: string | null;
      positionTitle?: string | null;
      providerRoleId?: string | null;
      notes?: string | null;
    },
  ): Promise<{
    application: JobApplication;
    employee: Employee;
    alreadyHired: boolean;
  }> {
    const application = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
      relations: ['job_posting'],
    });
    if (!application) {
      throw new NotFoundException('Job application not found');
    }
    if (application.job_posting?.organization_id !== organizationId) {
      throw new NotFoundException(
        'Job application not found for this organization',
      );
    }
    if (!application.applicant_user_id) {
      throw new BadRequestException(
        'Applicant has not yet created a user account — they must sign in or sign up with the email used to apply before they can be hired.',
      );
    }

    const offer = (application.offer_details ?? {}) as Record<string, unknown>;
    const internalSigningComplete = offer.internalSigningComplete;
    // Flag only exists when the offer had internal signers. If it's
    // explicitly `false`, block the hire. `true` or `null`/absent is fine.
    if (internalSigningComplete === false) {
      throw new BadRequestException(
        'Offer letter is still awaiting internal signatures. Complete all internal signers before hiring.',
      );
    }

    // Idempotent path: already hired → return the existing employee.
    if (application.status === 'hired') {
      const existing = await this.employeeRepository.findOne({
        where: {
          user_id: application.applicant_user_id,
          organization_id: organizationId,
        },
      });
      if (existing) {
        return { application, employee: existing, alreadyHired: true };
      }
      // Fall through to re-create if the row was deleted out of band.
    } else if (application.status !== 'offer_accepted') {
      throw new BadRequestException(
        `Cannot hire from status "${application.status}". Offer must be accepted first.`,
      );
    }

    // Resolve employment fields with precedence:
    //   1. explicit override from the hire button payload,
    //   2. value stored on offer_details,
    //   3. null.
    const coerceStr = (v: unknown): string | null => {
      if (typeof v !== 'string') return null;
      const t = v.trim();
      return t.length > 0 ? t : null;
    };
    const employmentType =
      overrides?.employmentType ?? coerceStr(offer.employmentType);
    const startDateStr = overrides?.startDate ?? coerceStr(offer.startDate);
    const startDate = startDateStr ? new Date(startDateStr) : null;
    const department = overrides?.department ?? null;
    const positionTitle =
      overrides?.positionTitle ?? coerceStr(application.job_posting?.title);
    const providerRoleId = overrides?.providerRoleId ?? null;
    const notes = overrides?.notes ?? null;

    // All writes go through a single transaction so a partial failure
    // (e.g. status UPDATE succeeds but EmployeeProfile insert crashes)
    // rolls the whole thing back — no half-hired employees with a
    // `offer_accepted` application, no Employee rows without a profile
    // stub.
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    let employee: Employee;
    let alreadyHired = application.status === 'hired';
    try {
      const employeeRepo = queryRunner.manager.getRepository(Employee);
      const profileRepo = queryRunner.manager.getRepository(EmployeeProfile);
      const applicationRepo = queryRunner.manager.getRepository(JobApplication);
      const userRepo = queryRunner.manager.getRepository(User);

      // Idempotent create: upsert-on-unique(user_id, organization_id).
      let existingEmployee = await employeeRepo.findOne({
        where: {
          user_id: application.applicant_user_id,
          organization_id: organizationId,
        },
      });
      if (!existingEmployee) {
        const newEmployee = employeeRepo.create({
          user_id: application.applicant_user_id,
          organization_id: organizationId,
          status: 'active',
          employment_type: employmentType,
          start_date: startDate,
          end_date: null,
          department,
          position_title: positionTitle,
          notes,
          provider_role_id: providerRoleId,
        });
        try {
          existingEmployee = await employeeRepo.save(newEmployee);
        } catch (err) {
          // Concurrent hire — unique violation. Re-read the row.
          const msg = err instanceof Error ? err.message : String(err);
          if (/duplicate|unique/i.test(msg)) {
            const raced = await employeeRepo.findOne({
              where: {
                user_id: application.applicant_user_id,
                organization_id: organizationId,
              },
            });
            if (raced) {
              existingEmployee = raced;
            } else {
              throw err;
            }
          } else {
            throw err;
          }
        }
      }
      employee = existingEmployee;

      // Minimal EmployeeProfile stub so the row exists for the employee to
      // edit. `name` is required; the rest is filled in by the employee on
      // their own profile page.
      const existingProfile = await profileRepo.findOne({
        where: { employee_id: employee.id },
      });
      if (!existingProfile) {
        let seedName = coerceStr(application.applicant_name);
        if (!seedName) {
          const user = await userRepo.findOne({
            where: { id: application.applicant_user_id },
          });
          seedName =
            [user?.firstName, user?.lastName]
              .filter(Boolean)
              .join(' ')
              .trim() ||
            user?.email ||
            'New Employee';
        }
        const profile = profileRepo.create({
          employee_id: employee.id,
          name: seedName,
          phone_number: coerceStr(application.applicant_phone),
        });
        try {
          await profileRepo.save(profile);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          // Unique (employee_id) — another request raced us. Safe to ignore.
          if (!/duplicate|unique/i.test(msg)) {
            throw err;
          }
        }
      }

      // Race-safe conditional UPDATE: only transitions from offer_accepted.
      // Skip the update if the row is already hired (idempotent path).
      if (!alreadyHired) {
        const result = await applicationRepo
          .createQueryBuilder()
          .update(JobApplication)
          .set({ status: 'hired' })
          .where('id = :id', { id: applicationId })
          .andWhere('status = :expected', { expected: 'offer_accepted' })
          .execute();
        if ((result.affected ?? 0) === 0) {
          // Re-read inside the transaction — a concurrent writer may have
          // flipped the row to `hired` already.
          const fresh = await applicationRepo.findOne({
            where: { id: applicationId },
          });
          if (fresh?.status === 'hired') {
            alreadyHired = true;
          } else {
            throw new BadRequestException(
              'This application has moved to a different state — refresh the page to see the current status.',
            );
          }
        }
      }

      await queryRunner.commitTransaction();
    } catch (err) {
      await queryRunner.rollbackTransaction();
      throw err;
    } finally {
      await queryRunner.release();
    }

    const freshApp = await this.jobApplicationRepository.findOne({
      where: { id: applicationId },
    });
    if (!freshApp) {
      throw new NotFoundException('Job application not found after hire');
    }

    // Fire welcome email (best-effort — failure should not roll back the hire).
    if (!alreadyHired) {
      try {
        const user = await this.userRepository.findOne({
          where: { id: application.applicant_user_id },
        });
        const toEmail = user?.email || application.applicant_email;
        if (toEmail) {
          const organizationName =
            await this.resolveOrganizationName(organizationId);
          const orgLogo =
            await this.companyProfileService.getOrganizationLogoBytes(
              organizationId,
            );
          await this.emailService.sendHireWelcomeEmail(
            toEmail,
            {
              applicantName:
                application.applicant_name ||
                [user?.firstName, user?.lastName]
                  .filter(Boolean)
                  .join(' ')
                  .trim() ||
                'there',
              jobTitle:
                application.job_posting?.title || positionTitle || 'your role',
              startDate: startDateStr ?? undefined,
              employmentType: employmentType ?? undefined,
              organizationName,
            },
            orgLogo,
          );
        }
      } catch {
        // Swallow — welcome email is a nice-to-have, not a blocker.
      }
    }

    return { application: freshApp, employee, alreadyHired };
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
      throw new NotFoundException(`Job application not found`);
    }
    if (application.job_posting?.organization_id !== organizationId) {
      throw new NotFoundException(
        `Job application not found for this organization`,
      );
    }
    const organizationName =
      dto.organizationName?.trim() ||
      (await this.resolveOrganizationName(organizationId));
    const orgLogo = await this.companyProfileService.getOrganizationLogoBytes(
      organizationId,
    );
    const frontendUrl =
      process.env.HOME_HEALTH_AI_URL || process.env.FRONTEND_URL || '';
    const portalBase = frontendUrl
      ? `${frontendUrl.replace(/\/$/, '')}/employee/jobs?view=applications&app=${encodeURIComponent(applicationId)}`
      : '';
    const confirmUrl = portalBase ? `${portalBase}&response=confirmed` : undefined;
    const declineUrl = portalBase ? `${portalBase}&response=unavailable` : undefined;
    try {
      await this.emailService.sendInterviewInviteEmail(
        dto.toEmail,
        {
          applicantName: dto.applicantName,
          jobTitle: dto.jobTitle,
          interviewDate: dto.interviewDate,
          interviewTime: dto.interviewTime,
          interviewMode: dto.interviewMode,
          interviewLocation: dto.interviewLocation,
          interviewDuration: dto.interviewDuration,
          message: dto.message,
          jobLocation: dto.jobLocation,
          jobType: dto.jobType,
          salaryRange: dto.salaryRange,
          jobDescription: dto.jobDescription,
          organizationName,
          contactName: dto.contactName,
          contactEmail: dto.contactEmail,
          contactPhone: dto.contactPhone,
          confirmUrl,
          declineUrl,
        },
        orgLogo,
      );
      return { message: 'Interview invite email sent successfully' };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('not configured')) {
        throw new BadRequestException(
          'Email is not configured.',
        );
      }
      throw new BadRequestException(`Failed to send interview invite email.`);
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
