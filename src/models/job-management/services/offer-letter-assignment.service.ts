import {
  BadRequestException,
  ForbiddenException,
  forwardRef,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { createHash, randomBytes } from 'crypto';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { OfferLetterAssignment } from '../entities/offer-letter-assignment.entity';
import {
  OfferLetterAssignmentRole,
  OfferRecipientType,
} from '../entities/offer-letter-assignment-role.entity';
import { OfferLetterFieldValue } from '../entities/offer-letter-field-value.entity';
import { CompetencyTemplate } from '../../organizations/document-workflow/entities/competency-template.entity';
import { DocumentWorkflowRole } from '../../organizations/document-workflow/entities/document-workflow-role.entity';
import { Organization } from '../../organizations/entities/organization.entity';
import { OrganizationCompanyProfileService } from '../../organizations/company-profile-setup/services/organization-company-profile.service';
import { JobApplication } from '../entities/job-application.entity';
import { User } from '../../../authentication/entities/user.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import {
  CreateOfferLetterAssignmentDto,
  OfferRoleAssigneeDto,
} from '../dto/create-offer-letter-assignment.dto';
import { FillOfferLetterFieldsDto } from '../dto/fill-offer-letter-fields.dto';
import { TemplatesService } from '../../organizations/document-workflow/services/templates.service';
import { EmailService } from '../../../common/services/email/email.service';
import { JobApplicationDocumentStorageService } from './job-application-document-storage.service';
import { OfferLetterArchiveService } from './offer-letter-archive.service';
import {
  findApplicantOfferLetterConsent,
  findRoleFillerOfferLetterConsent,
} from '../constants/esign-consent';

const FILL_TOKEN_TTL_DAYS = 30;

/**
 * Per-recipient outcome of the offer-letter emails fanned out when HR sends
 * an offer. Returned from create() so the HR-facing response can say
 * "offer created; 1 email failed to deliver" instead of pretending all went
 * through just because the offer row was persisted.
 */
export interface OfferEmailRecipientResult {
  kind: 'assignee' | 'applicant';
  email: string | null;
  status: 'sent' | 'failed' | 'skipped';
  reason?: string;
}
export interface OfferEmailDeliveryReport {
  sent: number;
  failed: number;
  recipients: OfferEmailRecipientResult[];
}

export interface TemplateFieldSnapshot {
  id: string;
  type: string;
  label?: string;
  placeholder?: string;
  required?: boolean;
  assignedRoleId?: string | null;
  page?: number;
  xPct?: number;
  yPct?: number;
  wPct?: number;
  hPct?: number;
  options?: string[];
  [k: string]: unknown;
}

export interface TemplateSnapshot {
  id: string;
  name: string;
  description?: string;
  roles: Array<{ id: string; name: string; color?: string; order?: number }>;
  document_fields: TemplateFieldSnapshot[];
  pdf_file_key?: string | null;
  pdf_original_name?: string | null;
}

@Injectable()
export class OfferLetterAssignmentService {
  private readonly logger = new Logger(OfferLetterAssignmentService.name);

  constructor(
    @InjectRepository(OfferLetterAssignment)
    private readonly assignmentRepo: Repository<OfferLetterAssignment>,
    @InjectRepository(OfferLetterAssignmentRole)
    private readonly roleRepo: Repository<OfferLetterAssignmentRole>,
    @InjectRepository(OfferLetterFieldValue)
    private readonly valueRepo: Repository<OfferLetterFieldValue>,
    @InjectRepository(CompetencyTemplate)
    private readonly templateRepo: Repository<CompetencyTemplate>,
    @InjectRepository(DocumentWorkflowRole)
    private readonly workflowRoleRepo: Repository<DocumentWorkflowRole>,
    @InjectRepository(JobApplication)
    private readonly applicationRepo: Repository<JobApplication>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(Organization)
    private readonly organizationRepo: Repository<Organization>,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaffRepo: Repository<OrganizationStaff>,
    private readonly templatesService: TemplatesService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly companyProfileService: OrganizationCompanyProfileService,
    private readonly jobApplicationDocumentStorage: JobApplicationDocumentStorageService,
    // Bidirectional dep: ArchiveService injects OfferLetterAssignmentService
    // for `bakeSignedPdf`. forwardRef lets Nest resolve the cycle at runtime.
    @Inject(forwardRef(() => OfferLetterArchiveService))
    private readonly archiveService: OfferLetterArchiveService,
  ) {}

  // ─── Creation ───────────────────────────────────────────────────────────

  /**
   * Instantiate a Document Workflow template for one job application.
   *
   * Freezes a snapshot of the template and creates one role-assignment row per
   * assignee. External-employee assignees receive a one-time fill token the
   * public fill page uses.
   */
  async create(
    orgId: string,
    applicationId: string,
    dto: CreateOfferLetterAssignmentDto,
    createdByUserId: string,
  ): Promise<OfferLetterAssignment> {
    const application = await this.applicationRepo.findOne({
      where: { id: applicationId },
      relations: ['job_posting'],
    });
    if (!application) throw new NotFoundException('Job application not found');
    // Closed applications can't receive a new offer — otherwise HR can
    // accidentally "send offer" to someone they already rejected or who
    // declined a previous offer, and the applicant then sees contradictory
    // status + offer data.
    const CLOSED_STATUSES = ['rejected', 'offer_declined', 'offer_accepted'];
    if (CLOSED_STATUSES.includes((application.status ?? '').toLowerCase())) {
      throw new BadRequestException(
        `Cannot send an offer for an application in "${application.status}" state. Reopen the application first.`,
      );
    }

    const template = await this.templateRepo.findOne({
      where: { id: dto.templateId, organization_id: orgId },
    });
    if (!template) throw new NotFoundException('Template not found');

    // All referenced role IDs must exist on the template and be valid DW roles.
    const templateRoleIds = new Set(template.roles.map((r) => r.id));
    const assigneeRoleIds = [...new Set(dto.assignees.map((a) => a.roleId))];
    const unknown = assigneeRoleIds.filter((id) => !templateRoleIds.has(id));
    if (unknown.length > 0) {
      throw new BadRequestException(
        'Some assignees target roles that do not belong to the selected template.',
      );
    }

    const roles = await this.workflowRoleRepo.find({
      where: { id: In(assigneeRoleIds) },
    });
    if (roles.length !== assigneeRoleIds.length) {
      throw new BadRequestException('One or more role IDs are invalid');
    }

    // Every role that the template uses in a field *must* have at least one assignee.
    const rolesUsedInFields = new Set<string>(
      (template.document_fields ?? [])
        .map((f) => (f as TemplateFieldSnapshot).assignedRoleId)
        .filter((x): x is string => !!x),
    );
    const missing = [...rolesUsedInFields].filter(
      (rid) => !assigneeRoleIds.includes(rid),
    );
    if (missing.length > 0) {
      const missingNames = template.roles
        .filter((r) => missing.includes(r.id))
        .map((r) => r.name);
      throw new BadRequestException(
        `Every template role must have at least one assignee. Missing: ${missingNames.join(', ')}`,
      );
    }

    const snapshot: TemplateSnapshot = {
      id: template.id,
      name: template.name,
      description: template.description,
      roles: template.roles as unknown as TemplateSnapshot['roles'],
      document_fields: template.document_fields as unknown as TemplateFieldSnapshot[],
      pdf_file_key: template.pdf_file_key,
      pdf_original_name: template.pdf_original_name,
    };

    const assignment = await this.assignmentRepo.save(
      this.assignmentRepo.create({
        organization_id: orgId,
        job_application_id: applicationId,
        template_id: template.id,
        template_snapshot: snapshot as unknown as Record<string, unknown>,
        status: 'sent',
        sent_at: new Date(),
        created_by: createdByUserId,
      }),
    );

    const roleRows = dto.assignees.map((a) => this.buildRoleRow(assignment.id, a));
    const savedRoles = await this.roleRepo.save(roleRows);

    // Partition role-fill rows up front — the split drives both the
    // persistent state (stay in offer_pending while internal signing
    // pending) and which emails go out now vs. later.
    const { internalRows, applicantRows, userById } =
      await this.partitionRolesByApplicant(savedRoles, application);

    // Persist offer metadata on the job application so downstream views (e.g.
    // SignedOfferViewerModal, status badges) continue to work.
    //
    // Sequential signing (Option B): if at least one internal role-filler
    // exists we park the application in `offer_pending` until they all
    // sign. When there are ZERO internal rows (e.g. template has no role
    // fields, or HR assigned only the applicant themselves) there's
    // nothing to wait for — transition directly to `offer_sent` so the
    // applicant can accept immediately.
    const existing = (application.offer_details ?? {}) as Record<string, unknown>;
    application.offer_details = {
      ...existing,
      ...(dto.offerDetails ?? {}),
      templateId: template.id,
      templateName: template.name,
      offerLetterAssignmentId: assignment.id,
      sentAt: new Date().toISOString(),
      internalSigningComplete: internalRows.length === 0,
    };
    const hasInternalSigners = internalRows.length > 0;
    if (
      application.status === 'pending' ||
      application.status === 'interview'
    ) {
      application.status = hasInternalSigners ? 'offer_pending' : 'offer_sent';
    }
    await this.applicationRepo.save(application);

    const emailDelivery: OfferEmailDeliveryReport = await this.notifyInternalSigners(
      application,
      template.name,
      internalRows,
      userById,
    );

    // Applicant role-fill emails fire at create time (in parallel with
    // internal signers) so the applicant can sign their portion without
    // waiting for supervisors to finish. Previously these were deferred
    // inside `fireApplicantHandoff`, which meant HR had to wait for every
    // supervisor to sign before the applicant was even notified — making
    // offers with multiple signers appear "stuck" from the applicant's
    // view.
    await this.notifyApplicantRoleFillers(
      application,
      template.name,
      applicantRows,
      userById,
      emailDelivery,
    );

    // When no internal signing is required, also fire the applicant's
    // "review and accept" decision email straight away. Otherwise the
    // decision email fires later from `reconcileCompletion` once the last
    // internal signature lands — reviewing an unsigned offer would be
    // confusing.
    if (!hasInternalSigners) {
      await this.fireApplicantHandoff(
        application,
        template.name,
        /* applicantRows */ [], // role-fill already sent above
        userById,
        emailDelivery,
      );
    }

    const result = await this.findOne(orgId, assignment.id);
    // Attach delivery results as a transient property so the controller can
    // surface bounce / SMTP failures back to the HR user instead of the
    // classic "everything looked fine but nobody got the email" trap.
    (result as unknown as {
      email_delivery?: typeof emailDelivery;
    }).email_delivery = emailDelivery;
    return result;
  }

  /** Per-recipient email delivery outcome reported back to HR. */
  private buildFailureMessage(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
  }

  /**
   * Split role-fill rows into "internal signers" (HR / supervisor / CEO /
   * external-signer) and "applicant rows" (the candidate's own row when HR
   * pre-selected them on the Employee role). The split drives the sequential
   * signing flow: internal signers are notified at offer creation, and the
   * applicant — along with any applicant role-fill row — is notified only
   * after every internal row is completed.
   *
   * A row is considered an applicant row when either the row's `user_id`
   * matches `application.applicant_user_id` (durable link set at apply
   * time) or the row-user's email matches `application.applicant_email`
   * case-insensitively (fallback for guest-applies linked later).
   */
  private async partitionRolesByApplicant(
    roleRows: OfferLetterAssignmentRole[],
    application: JobApplication,
  ): Promise<{
    internalRows: OfferLetterAssignmentRole[];
    applicantRows: OfferLetterAssignmentRole[];
    userById: Map<string, User>;
  }> {
    const userIds = [...new Set(roleRows.map((r) => r.user_id))];
    const users = userIds.length
      ? await this.userRepo.find({ where: { id: In(userIds) } })
      : [];
    const userById = new Map(users.map((u) => [u.id, u]));
    const applicantEmail = application.applicant_email?.trim().toLowerCase();
    const applicantUserId = application.applicant_user_id;
    const internalRows: OfferLetterAssignmentRole[] = [];
    const applicantRows: OfferLetterAssignmentRole[] = [];
    for (const row of roleRows) {
      const isApplicant = (() => {
        if (applicantUserId && row.user_id === applicantUserId) return true;
        const user = userById.get(row.user_id);
        if (
          applicantEmail &&
          user?.email?.toLowerCase() === applicantEmail
        ) {
          return true;
        }
        return false;
      })();
      if (isApplicant) applicantRows.push(row);
      else internalRows.push(row);
    }
    return { internalRows, applicantRows, userById };
  }

  /**
   * Send an offer letter "please sign" email to each internal role-filler
   * (HR / supervisor / CEO / external-signer). Intentionally does NOT notify
   * the applicant — Option B's sequential flow notifies them separately,
   * only after every internal signature is in. Returns a per-recipient
   * delivery report so the HR-facing create response can surface SMTP
   * bounces instead of pretending all mail went through.
   *
   * `roleRows` should contain only internal rows (applicant rows filtered
   * out by `partitionRolesByApplicant`). `userByIdCache` is passed in from
   * the partition call to avoid a redundant users lookup.
   */
  private async notifyInternalSigners(
    application: JobApplication,
    templateName: string,
    roleRows: OfferLetterAssignmentRole[],
    userByIdCache: Map<string, User>,
  ): Promise<OfferEmailDeliveryReport> {
    const report: OfferEmailDeliveryReport = {
      sent: 0,
      failed: 0,
      recipients: [],
    };
    if (!roleRows.length) return report;

    const frontendBase = (
      this.configService.get<string>('HOME_HEALTH_AI_URL') ?? ''
    ).replace(/\/$/, '');

    const userById = userByIdCache;

    const offerDetails = (application.offer_details ?? {}) as Record<string, unknown>;

    const orgId = application.job_posting?.organization_id;
    const [organizationName, orgLogo] = orgId
      ? await Promise.all([
          this.resolveOrganizationName(orgId),
          this.companyProfileService.getOrganizationLogoBytes(orgId),
        ])
      : [undefined, null];

    for (const row of roleRows) {
      const user = userById.get(row.user_id);
      if (!user?.email) {
        report.recipients.push({
          kind: 'assignee',
          email: null,
          status: 'skipped',
          reason: 'No email on file for this assignee.',
        });
        continue;
      }

      const fillUrl = this.buildFillUrl(frontendBase, row);
      const recipientName = this.fullName(user) || application.applicant_name || 'there';

      try {
        await this.emailService.sendOfferLetterEmail(
          user.email,
          {
            applicantName: recipientName,
            // The template renders the signer email with candidate context
            // ("sign the offer letter prepared for <candidate>"). Passing the
            // candidate separately from the recipient keeps the greeting
            // correct ("Dear <supervisor>") while letting the body name the
            // person whose offer is being signed.
            candidateName: application.applicant_name || undefined,
            jobTitle: application.job_posting?.title ?? templateName,
            salary: typeof offerDetails.salary === 'string' ? offerDetails.salary : '',
            startDate:
              typeof offerDetails.startDate === 'string' ? offerDetails.startDate : '',
            offerContent: '',
            benefits:
              typeof offerDetails.benefits === 'string' ? offerDetails.benefits : undefined,
            responseDeadline:
              typeof offerDetails.responseDeadline === 'string'
                ? offerDetails.responseDeadline
                : undefined,
            employmentType:
              (offerDetails.employmentType as
                | 'full_time'
                | 'part_time'
                | 'contract'
                | 'temporary'
                | 'internship'
                | undefined) ?? undefined,
            message:
              typeof offerDetails.message === 'string' ? offerDetails.message : undefined,
            jobLocation: application.job_posting?.location ?? undefined,
            organizationName,
            fillUrl,
            recipientType: row.recipient_type,
          },
          orgLogo,
        );
        report.sent += 1;
        report.recipients.push({
          kind: 'assignee',
          email: user.email,
          status: 'sent',
        });
      } catch (err) {
        report.failed += 1;
        const reason = this.buildFailureMessage(err);
        this.logger.warn(
          `Offer letter email to user ${row.user_id} (${user.email}) failed: ${reason}`,
        );
        report.recipients.push({
          kind: 'assignee',
          email: user.email,
          status: 'failed',
          reason,
        });
      }
    }

    // Note: applicant notifications are intentionally NOT fired here. Option
    // B's sequential flow sends the applicant's "review and accept" email
    // only after every internal row completes — see
    // `fireApplicantHandoffIfReady()` which is called from `create()` when
    // there are zero internal signers and from `reconcileCompletion()` when
    // the last internal signature lands.
    return report;
  }

  /**
   * Fire the applicant-facing notifications once internal signing is done:
   *   1. `notifyApplicant` — the "review and accept" email the candidate
   *      uses to enter the accept/decline flow on My Applications.
   *   2. The regular role-fill email(s) to any applicant row on the
   *      assignment (when HR pre-selected the applicant on the Employee
   *      role in the Role Assignment modal) — delayed so the applicant
   *      isn't asked to sign before the org has authorized the document.
   *
   * Results are appended to the caller's delivery report.
   */
  /**
   * Send "please sign your portion" emails to applicant role-filler rows
   * (i.e. role assignments where the filler is the applicant themselves,
   * typically the `employee` recipient_type). Fires immediately at offer
   * creation so the applicant can sign in parallel with internal signers
   * rather than waiting for them to finish.
   *
   * This is the role-fill half of what used to live inside
   * `fireApplicantHandoff`. The decision ("review and accept") half still
   * fires later via `fireApplicantHandoffIfReady`.
   */
  private async notifyApplicantRoleFillers(
    application: JobApplication,
    templateName: string,
    applicantRows: OfferLetterAssignmentRole[],
    userByIdCache: Map<string, User>,
    report: OfferEmailDeliveryReport,
  ): Promise<void> {
    if (!applicantRows.length) return;

    const frontendBase = (
      this.configService.get<string>('HOME_HEALTH_AI_URL') ?? ''
    ).replace(/\/$/, '');
    const offerDetails = (application.offer_details ?? {}) as Record<
      string,
      unknown
    >;
    const orgId = application.job_posting?.organization_id;
    const [organizationName, orgLogo] = orgId
      ? await Promise.all([
          this.resolveOrganizationName(orgId),
          this.companyProfileService.getOrganizationLogoBytes(orgId),
        ])
      : [undefined, null];

    for (const row of applicantRows) {
      const user = userByIdCache.get(row.user_id);
      if (!user?.email) {
        report.recipients.push({
          kind: 'assignee',
          email: null,
          status: 'skipped',
          reason: 'No email on file for this applicant role-filler.',
        });
        continue;
      }
      const fillUrl = this.buildFillUrl(frontendBase, row);
      const recipientName =
        this.fullName(user) || application.applicant_name || 'there';
      try {
        await this.emailService.sendOfferLetterEmail(
          user.email,
          {
            applicantName: recipientName,
            candidateName: application.applicant_name || undefined,
            jobTitle: application.job_posting?.title ?? templateName,
            salary:
              typeof offerDetails.salary === 'string' ? offerDetails.salary : '',
            startDate:
              typeof offerDetails.startDate === 'string'
                ? offerDetails.startDate
                : '',
            offerContent: '',
            benefits:
              typeof offerDetails.benefits === 'string'
                ? offerDetails.benefits
                : undefined,
            responseDeadline:
              typeof offerDetails.responseDeadline === 'string'
                ? offerDetails.responseDeadline
                : undefined,
            employmentType:
              (offerDetails.employmentType as
                | 'full_time'
                | 'part_time'
                | 'contract'
                | 'temporary'
                | 'internship'
                | undefined) ?? undefined,
            message:
              typeof offerDetails.message === 'string'
                ? offerDetails.message
                : undefined,
            jobLocation: application.job_posting?.location ?? undefined,
            organizationName,
            fillUrl,
            recipientType: row.recipient_type,
          },
          orgLogo,
        );
        report.sent += 1;
        report.recipients.push({
          kind: 'assignee',
          email: user.email,
          status: 'sent',
        });
      } catch (err) {
        report.failed += 1;
        const reason = this.buildFailureMessage(err);
        this.logger.warn(
          `Applicant role-fill email to user ${row.user_id} (${user.email}) failed: ${reason}`,
        );
        report.recipients.push({
          kind: 'assignee',
          email: user.email,
          status: 'failed',
          reason,
        });
      }
    }
  }

  private async fireApplicantHandoff(
    application: JobApplication,
    templateName: string,
    applicantRows: OfferLetterAssignmentRole[],
    userByIdCache: Map<string, User>,
    report: OfferEmailDeliveryReport,
  ): Promise<void> {
    const frontendBase = (
      this.configService.get<string>('HOME_HEALTH_AI_URL') ?? ''
    ).replace(/\/$/, '');
    const offerDetails = (application.offer_details ?? {}) as Record<string, unknown>;
    const orgId = application.job_posting?.organization_id;
    const [organizationName, orgLogo] = orgId
      ? await Promise.all([
          this.resolveOrganizationName(orgId),
          this.companyProfileService.getOrganizationLogoBytes(orgId),
        ])
      : [undefined, null];

    // 1. "Review and accept your offer" email to the applicant.
    const applicantResult = await this.notifyApplicant({
      application,
      templateName,
      offerDetails,
      organizationName,
      orgLogo,
      frontendBase,
      assigneeEmails: new Set<string>(),
    });
    if (applicantResult) {
      if (applicantResult.status === 'sent') report.sent += 1;
      if (applicantResult.status === 'failed') report.failed += 1;
      report.recipients.push(applicantResult);
    }

    // 2. Role-fill email to the applicant's role row (they need to sign
    //    their portion too). The role-fill link flows through the normal
    //    assignee routing so the applicant lands on the Offer Letter tab.
    for (const row of applicantRows) {
      const user = userByIdCache.get(row.user_id);
      if (!user?.email) continue;
      const fillUrl = this.buildFillUrl(frontendBase, row);
      const recipientName =
        this.fullName(user) || application.applicant_name || 'there';
      try {
        await this.emailService.sendOfferLetterEmail(
          user.email,
          {
            applicantName: recipientName,
            candidateName: application.applicant_name || undefined,
            jobTitle: application.job_posting?.title ?? templateName,
            salary: typeof offerDetails.salary === 'string' ? offerDetails.salary : '',
            startDate:
              typeof offerDetails.startDate === 'string'
                ? offerDetails.startDate
                : '',
            offerContent: '',
            benefits:
              typeof offerDetails.benefits === 'string'
                ? offerDetails.benefits
                : undefined,
            responseDeadline:
              typeof offerDetails.responseDeadline === 'string'
                ? offerDetails.responseDeadline
                : undefined,
            employmentType:
              (offerDetails.employmentType as
                | 'full_time'
                | 'part_time'
                | 'contract'
                | 'temporary'
                | 'internship'
                | undefined) ?? undefined,
            message:
              typeof offerDetails.message === 'string'
                ? offerDetails.message
                : undefined,
            jobLocation: application.job_posting?.location ?? undefined,
            organizationName,
            fillUrl,
            recipientType: row.recipient_type,
          },
          orgLogo,
        );
        report.sent += 1;
        report.recipients.push({
          kind: 'assignee',
          email: user.email,
          status: 'sent',
        });
      } catch (err) {
        report.failed += 1;
        const reason = this.buildFailureMessage(err);
        this.logger.warn(
          `Applicant role-fill email to user ${row.user_id} (${user.email}) failed: ${reason}`,
        );
        report.recipients.push({
          kind: 'assignee',
          email: user.email,
          status: 'failed',
          reason,
        });
      }
    }
  }

  /**
   * Send the offer letter email directly to the applicant. Unlike the
   * assignee emails, the applicant's CTA points at their "My Applications"
   * page where they can accept or decline. The link is only included when the
   * applicant has a matching user account; external applicants with no user
   * row get the email without a CTA button (they can still reply or contact
   * the HR point of contact shown in the message).
   */
  private async notifyApplicant(args: {
    application: JobApplication;
    templateName: string;
    offerDetails: Record<string, unknown>;
    organizationName?: string;
    orgLogo: Awaited<
      ReturnType<OrganizationCompanyProfileService['getOrganizationLogoBytes']>
    >;
    frontendBase: string;
    assigneeEmails: Set<string>;
  }): Promise<OfferEmailRecipientResult | null> {
    const {
      application,
      templateName,
      offerDetails,
      organizationName,
      orgLogo,
      frontendBase,
      assigneeEmails,
    } = args;

    const applicantEmail = application.applicant_email?.trim();
    if (!applicantEmail) {
      return {
        kind: 'applicant',
        email: null,
        status: 'skipped',
        reason: 'Application has no applicant_email on file.',
      };
    }
    if (assigneeEmails.has(applicantEmail.toLowerCase())) {
      // Applicant is also a role assignee (e.g. added as external_employee) —
      // they already got an email via the assignee loop. Dedup here rather
      // than double-notify.
      return null;
    }

    // Link straight to the applicant's My Applications view with the target
    // application pre-expanded (via `app=<id>`). The expanded card shows the
    // offer details inline — PDF link + accept/decline + continue-to-onboarding
    // — so the applicant handles everything from a single surface. When the
    // user is not authenticated yet, the 401 interceptor bounces them to
    // /login?next=... and returns them here after login.
    const reviewUrl = frontendBase
      ? `${frontendBase}/employee/jobs?view=applications&app=${encodeURIComponent(application.id)}`
      : undefined;

    try {
      await this.emailService.sendOfferLetterEmail(
        applicantEmail,
        {
          applicantName: application.applicant_name || 'there',
          // Recipient and candidate are the same person on the applicant
          // email, but we set both explicitly so the template doesn't have
          // to fall back silently.
          candidateName: application.applicant_name || undefined,
          jobTitle: application.job_posting?.title ?? templateName,
          salary: typeof offerDetails.salary === 'string' ? offerDetails.salary : '',
          startDate:
            typeof offerDetails.startDate === 'string' ? offerDetails.startDate : '',
          offerContent: '',
          benefits:
            typeof offerDetails.benefits === 'string' ? offerDetails.benefits : undefined,
          responseDeadline:
            typeof offerDetails.responseDeadline === 'string'
              ? offerDetails.responseDeadline
              : undefined,
          employmentType:
            (offerDetails.employmentType as
              | 'full_time'
              | 'part_time'
              | 'contract'
              | 'temporary'
              | 'internship'
              | undefined) ?? undefined,
          message:
            typeof offerDetails.message === 'string' ? offerDetails.message : undefined,
          jobLocation: application.job_posting?.location ?? undefined,
          organizationName,
          fillUrl: reviewUrl,
          recipientType: 'applicant',
        },
        orgLogo,
      );
      return { kind: 'applicant', email: applicantEmail, status: 'sent' };
    } catch (err) {
      const reason = this.buildFailureMessage(err);
      this.logger.warn(
        `Offer letter email to applicant ${applicantEmail} failed: ${reason}`,
      );
      return {
        kind: 'applicant',
        email: applicantEmail,
        status: 'failed',
        reason,
      };
    }
  }

  /**
   * Fetch the org's display name for email branding. Returns undefined when
   * the org has no name set so the template falls back to the default.
   */
  private async resolveOrganizationName(
    organizationId: string,
  ): Promise<string | undefined> {
    const org = await this.organizationRepo.findOne({
      where: { id: organizationId },
      select: ['id', 'organization_name'],
    });
    return org?.organization_name?.trim() || undefined;
  }

  private buildFillUrl(
    frontendBase: string,
    row: OfferLetterAssignmentRole,
  ): string {
    // External employees land on a fully-public token page — no login needed.
    if (row.recipient_type === 'external_employee' && row.fill_token) {
      return `${frontendBase}/offer-letter/fill/${row.fill_token}`;
    }
    // Authenticated recipients (employees, supervisors) are routed through a
    // friendly landing page that prompts them to log in when needed and
    // forwards them to the right in-app destination once authenticated.
    const target =
      row.recipient_type === 'employee'
        ? '/employee/jobs?view=offer-letters'
        : '/organization/document-workflow';
    return `${frontendBase}/offer-letter/open?to=${encodeURIComponent(target)}`;
  }

  private fullName(user: User): string {
    const first = (user as unknown as { firstName?: string }).firstName ?? '';
    const last = (user as unknown as { lastName?: string }).lastName ?? '';
    return `${first} ${last}`.trim();
  }

  private buildRoleRow(
    assignmentId: string,
    a: OfferRoleAssigneeDto,
  ): OfferLetterAssignmentRole {
    const row = this.roleRepo.create({
      assignment_id: assignmentId,
      role_id: a.roleId,
      user_id: a.userId,
      recipient_type: a.recipientType as OfferRecipientType,
    });

    if (a.recipientType === 'external_employee') {
      row.fill_token = randomBytes(48).toString('base64url');
      const expires = new Date();
      expires.setDate(expires.getDate() + FILL_TOKEN_TTL_DAYS);
      row.fill_token_expires_at = expires;
    }
    return row;
  }

  // ─── Reads ──────────────────────────────────────────────────────────────

  async findOne(orgId: string, id: string): Promise<OfferLetterAssignment> {
    const a = await this.assignmentRepo.findOne({
      where: { id, organization_id: orgId },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    return this.decorate(a);
  }

  async findForApplication(
    orgId: string,
    applicationId: string,
  ): Promise<OfferLetterAssignment[]> {
    const rows = await this.assignmentRepo.find({
      where: { organization_id: orgId, job_application_id: applicationId },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
      order: { created_at: 'DESC' },
    });
    return rows.map((r) => this.decorate(r));
  }

  /**
   * All offer letter assignments where a user is listed as an assignee —
   * powers the employee Job tab's "Offer Letter" sub-tab.
   *
   * Each returned assignment is augmented with `myRoles` — the role rows on
   * that assignment where `user_id === viewer`. This lets the UI render the
   * correct filler without having to reconcile client-side user ids against
   * backend role rows.
   */
  /**
   * Admin-scoped equivalent of `findForUser` — returns role-filler assignments
   * for a specific user, but constrained to a single organization. Powers the
   * org admin's Signed Documents tab so HR can see what offer letters an
   * employee has signed *as a role filler* (e.g. as a Manager signing for
   * someone else's offer). Uses the same `myRoles` decoration so the frontend
   * can reuse the same DTO shape.
   */
  async findForUserInOrganization(
    orgId: string,
    userId: string,
  ): Promise<Array<OfferLetterAssignment & { myRoles: OfferLetterAssignmentRole[] }>> {
    const roleRows = await this.roleRepo.find({
      where: { user_id: userId },
      order: { created_at: 'DESC' },
    });
    if (!roleRows.length) return [];
    const assignmentIds = [...new Set(roleRows.map((r) => r.assignment_id))];
    const assignments = await this.assignmentRepo.find({
      where: { id: In(assignmentIds), organization_id: orgId },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
      order: { created_at: 'DESC' },
    });

    // Dedup against assignments where the same user is the candidate on the
    // underlying job application — the org admin sees those via the candidate
    // path (job applications API) so we don't want to surface them twice.
    const applicationIds = [
      ...new Set(
        assignments
          .map((a) => a.job_application_id)
          .filter((id): id is string => !!id),
      ),
    ];
    const [user, applications] = await Promise.all([
      this.userRepo.findOne({ where: { id: userId } }),
      applicationIds.length
        ? this.applicationRepo.find({
            where: { id: In(applicationIds) },
            select: ['id', 'applicant_user_id', 'applicant_email'],
          })
        : Promise.resolve([] as JobApplication[]),
    ]);
    const userEmail = user?.email?.toLowerCase() ?? null;
    const ownedApplicationIds = new Set(
      applications
        .filter((app) => {
          if (app.applicant_user_id && app.applicant_user_id === userId) return true;
          if (userEmail && app.applicant_email?.toLowerCase() === userEmail) {
            return true;
          }
          return false;
        })
        .map((app) => app.id),
    );

    return assignments
      .filter((a) => {
        if (a.status === 'voided') return false;
        if (
          a.job_application_id &&
          ownedApplicationIds.has(a.job_application_id)
        ) {
          return false;
        }
        return true;
      })
      .map((a) => {
        const decorated = this.decorate(a);
        const myRoles = decorated.roleAssignments.filter(
          (r) => r.user_id === userId,
        );
        return Object.assign(decorated, { myRoles });
      });
  }

  async findForUser(
    userId: string,
  ): Promise<Array<OfferLetterAssignment & { myRoles: OfferLetterAssignmentRole[] }>> {
    const roleRows = await this.roleRepo.find({
      where: { user_id: userId },
      order: { created_at: 'DESC' },
    });
    if (!roleRows.length) return [];
    const assignmentIds = [...new Set(roleRows.map((r) => r.assignment_id))];
    const assignments = await this.assignmentRepo.find({
      where: { id: In(assignmentIds) },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
      order: { created_at: 'DESC' },
    });

    // The "Offer Letters to Fill" tab is for role-fillers acting on someone
    // else's offer (HR signing, supervisor acknowledging, etc.). When the
    // current user is the applicant on the underlying job application, the
    // offer is already surfaced on My Applications with its own Sign /
    // Upload UX — showing it here too is a confusing duplicate and inflates
    // the badge count. Look up the owning applications and drop any
    // assignment the caller owns as the applicant.
    //
    // We also drop voided assignments because a voided offer should never
    // need action; they still show on the org-side assignments list where
    // HR manages the lifecycle.
    const applicationIds = [
      ...new Set(
        assignments
          .map((a) => a.job_application_id)
          .filter((id): id is string => !!id),
      ),
    ];
    const [user, applications] = await Promise.all([
      this.userRepo.findOne({ where: { id: userId } }),
      applicationIds.length
        ? this.applicationRepo.find({
            where: { id: In(applicationIds) },
            select: ['id', 'applicant_user_id', 'applicant_email'],
          })
        : Promise.resolve([] as JobApplication[]),
    ]);
    const userEmail = user?.email?.toLowerCase() ?? null;
    const ownedApplicationIds = new Set(
      applications
        .filter((app) => {
          if (app.applicant_user_id && app.applicant_user_id === userId) return true;
          if (userEmail && app.applicant_email?.toLowerCase() === userEmail) {
            return true;
          }
          return false;
        })
        .map((app) => app.id),
    );

    return assignments
      .filter((a) => {
        if (a.status === 'voided') return false;
        if (
          a.job_application_id &&
          ownedApplicationIds.has(a.job_application_id)
        ) {
          return false;
        }
        return true;
      })
      .map((a) => {
        const decorated = this.decorate(a);
        const myRoles = decorated.roleAssignments.filter(
          (r) => r.user_id === userId,
        );
        // Rewrite pdfUrl to the assignee-scoped endpoint so the browser can
        // fetch the PDF without hitting the HR-only template endpoint.
        const snapshot = decorated.template_snapshot as unknown as TemplateSnapshot & {
          pdfUrl?: string;
        };
        if (snapshot?.pdf_file_key) {
          snapshot.pdfUrl = `/v1/api/me/offer-letter-assignments/${decorated.id}/pdf`;
          decorated.template_snapshot = snapshot as unknown as Record<string, unknown>;
        }
        return Object.assign(decorated, { myRoles });
      });
  }

  /**
   * Fetch the offer letter assignment attached to a job application, scoped
   * to the applicant of that application. Unlike `findForUser` (which filters
   * by `offer_letter_assignment_roles.user_id`), the applicant is not one of
   * the assignees — their authorisation is based on owning the job application.
   *
   * Returns the same shape as `findForUser` (single element) so the frontend
   * can reuse the OfferLetterFiller component in read-only mode to render the
   * template PDF with signature/field overlays. The `pdfUrl` is rewritten to
   * the applicant-scoped endpoint so the browser fetches bytes authorised by
   * the applicant's JWT.
   */
  async findForApplicant(
    userId: string,
    applicationId: string,
  ): Promise<(OfferLetterAssignment & { myRoles: OfferLetterAssignmentRole[] }) | null> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user?.email) {
      throw new ForbiddenException('Unauthorized');
    }
    const application = await this.applicationRepo.findOne({
      where: { id: applicationId },
    });
    if (!application) throw new NotFoundException('Job application not found');
    if (!this.applicantOwnsApplication(userId, user.email, application)) {
      this.logger.warn(
        `findForApplicant ownership check failed: userId=${userId}, user.email=${this.redactEmail(user.email)}, ` +
          `applicant_user_id=${application.applicant_user_id ?? 'null'}, applicant_email=${this.redactEmail(application.applicant_email ?? '')}`,
      );
      throw new ForbiddenException(
        'You can only view the offer letter for your own application.',
      );
    }
    const offerDetails = (application.offer_details ?? {}) as Record<string, unknown>;
    const assignmentId =
      typeof offerDetails.offerLetterAssignmentId === 'string'
        ? offerDetails.offerLetterAssignmentId
        : null;
    if (!assignmentId) return null;

    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
    });
    if (!a) return null;

    const decorated = this.decorate(a);
    // Point the in-app viewer at the raw template bytes (`?format=raw`).
    // OfferLetterFiller renders its own field overlays on top of the PDF,
    // so we don't want the server-rendered variant here — that would draw
    // every label twice. The Download / Open-in-browser buttons in the
    // applicant modal hit this same endpoint without the query param and
    // get the rendered version by default.
    const snapshot = decorated.template_snapshot as unknown as TemplateSnapshot & {
      pdfUrl?: string;
    };
    if (snapshot?.pdf_file_key) {
      snapshot.pdfUrl = `/api/job-management/me/job-applications/${application.id}/offer-letter/pdf?format=raw`;
      decorated.template_snapshot = snapshot as unknown as Record<string, unknown>;
    }
    // The applicant is not one of the role assignees, so `myRoles` is always
    // empty. Returning an empty array keeps the response shape identical to
    // `findForUser` so the frontend can reuse the same types.
    return Object.assign(decorated, { myRoles: [] as OfferLetterAssignmentRole[] });
  }

  async findByFillToken(token: string): Promise<{
    assignment: OfferLetterAssignment;
    roleAssignment: OfferLetterAssignmentRole;
  }> {
    const roleAssignment = await this.roleRepo.findOne({
      where: { fill_token: token },
      relations: ['role'],
    });
    if (!roleAssignment) throw new NotFoundException('Invalid fill token');
    if (
      roleAssignment.fill_token_expires_at &&
      roleAssignment.fill_token_expires_at.getTime() < Date.now()
    ) {
      throw new ForbiddenException('Fill token has expired');
    }

    const a = await this.assignmentRepo.findOne({
      where: { id: roleAssignment.assignment_id },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    const decorated = this.decorate(a);
    // Public caller — rewrite pdfUrl to the token-gated endpoint so the
    // browser can fetch the PDF without a JWT.
    const snapshot = decorated.template_snapshot as unknown as TemplateSnapshot & {
      pdfUrl?: string;
    };
    if (snapshot?.pdf_file_key) {
      snapshot.pdfUrl = `/v1/api/offer-letter/fill/${token}/pdf`;
      decorated.template_snapshot = snapshot as unknown as Record<string, unknown>;
    }
    return { assignment: decorated, roleAssignment };
  }

  // ─── PDF streaming (role-scoped) ────────────────────────────────────────

  /**
   * Stream the template PDF for an assignment the caller is an assignee on.
   * Used by `/v1/api/me/offer-letter-assignments/:id/pdf`.
   */
  async getPdfForAssignee(
    assignmentId: string,
    userId: string,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string; fileName: string }> {
    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['roleAssignments'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    const allowed = a.roleAssignments.some((r) => r.user_id === userId);
    if (!allowed) {
      throw new ForbiddenException('You are not assigned to this offer letter.');
    }
    return this.streamSnapshotPdf(a);
  }

  /**
   * Render the fully-signed PDF for an assignment WITHOUT auth checks.
   * Internal-use only — meant for server-side consumers (e.g. the post-
   * completion archive into the employee's HR File). Reuses the same
   * field-overlay baking pipeline the applicant-facing endpoint uses, so
   * the bytes match what the applicant downloaded after signing.
   */
  async bakeSignedPdf(
    assignmentId: string,
  ): Promise<{ buffer: Buffer; contentType: string; fileName: string }> {
    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['fieldValues'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    const application = await this.applicationRepo.findOne({
      where: { id: a.job_application_id },
    });
    if (!application) throw new NotFoundException('Job application not found');
    const applicantSignature = this.extractApplicantSignature(application);
    return this.renderPdfWithFieldOverlays(a, { applicantSignature });
  }

  /**
   * Return the offer letter PDF to the applicant **with field overlays baked
   * in** — signature placeholders, labels and any values already filled by
   * assignees are drawn directly into the PDF bytes via pdf-lib. This is
   * necessary because the template PDF itself only carries the body text;
   * field positions are metadata the frontend normally renders as HTML
   * overlays on top of a react-pdf page. If we streamed raw bytes to the
   * applicant, they'd see the text but no signature boxes — exactly the
   * issue that surfaces when they open or download the file in a browser.
   *
   * Unlike `getPdfForAssignee` (which expects an assignee filling their role
   * via the react-pdf editor), the applicant just views/downloads the file,
   * so the rendered output is what they need.
   *
   * Authorisation: caller's email must match `applicant_email`, or the auth'd
   * user id must match `applicant_user_id` on the application.
   */
  async getPdfForApplicant(
    userId: string,
    applicationId: string,
    opts: { raw?: boolean } = {},
  ): Promise<{ buffer: Buffer; contentType: string; fileName: string }> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user?.email) {
      throw new ForbiddenException('Unauthorized');
    }
    const application = await this.applicationRepo.findOne({
      where: { id: applicationId },
    });
    if (!application) throw new NotFoundException('Job application not found');
    if (!this.applicantOwnsApplication(userId, user.email, application)) {
      this.logger.warn(
        `getPdfForApplicant ownership check failed: userId=${userId}, user.email=${this.redactEmail(user.email)}, ` +
          `applicant_user_id=${application.applicant_user_id ?? 'null'}, applicant_email=${this.redactEmail(application.applicant_email ?? '')}`,
      );
      throw new ForbiddenException(
        'You can only view the offer letter for your own application.',
      );
    }
    const offerDetails = (application.offer_details ?? {}) as Record<string, unknown>;
    const assignmentId =
      typeof offerDetails.offerLetterAssignmentId === 'string'
        ? offerDetails.offerLetterAssignmentId
        : null;
    if (!assignmentId) {
      throw new NotFoundException('No offer letter attached to this application');
    }
    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['fieldValues'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    if (opts.raw) {
      // Raw template bytes — used by the in-app viewer, which layers its
      // own react-pdf field overlays on top; baking them server-side too
      // would duplicate every label.
      const { stream, contentType, fileName } = await this.streamSnapshotPdf(a);
      const buffer = await this.collectStreamToBuffer(stream);
      return { buffer, contentType, fileName };
    }
    // Default: rendered bytes with field overlays baked in — what the user
    // downloads or opens in their browser's native PDF viewer.
    const applicantSignature = this.extractApplicantSignature(application);
    return this.renderPdfWithFieldOverlays(a, { applicantSignature });
  }

  /**
   * HR-side version of getPdfForApplicant: return the rendered offer letter
   * PDF (signature + overlays baked in) for HR of the owning organization.
   * Auth is scoped by the route guard; this method only enforces that the
   * application actually belongs to the claimed org so HR of org A can't
   * probe org B's offers.
   */
  async getPdfForOrgApplication(
    orgId: string,
    applicationId: string,
  ): Promise<{ buffer: Buffer; contentType: string; fileName: string }> {
    const application = await this.applicationRepo.findOne({
      where: { id: applicationId },
      relations: ['job_posting'],
    });
    if (!application) throw new NotFoundException('Job application not found');
    if (application.job_posting?.organization_id !== orgId) {
      throw new NotFoundException('Job application not found for this organization');
    }
    const offerDetails = (application.offer_details ?? {}) as Record<string, unknown>;
    const assignmentId =
      typeof offerDetails.offerLetterAssignmentId === 'string'
        ? offerDetails.offerLetterAssignmentId
        : null;
    if (!assignmentId) {
      throw new NotFoundException('No offer letter attached to this application');
    }
    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['fieldValues'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    const applicantSignature = this.extractApplicantSignature(application);
    return this.renderPdfWithFieldOverlays(a, { applicantSignature });
  }

  /**
   * Pull the applicant's e-signed signature off the application's offer
   * details JSON in a type-safe way. Returns null when missing or malformed.
   */
  private extractApplicantSignature(
    application: JobApplication,
  ): { dataUrl: string; signedAt?: string } | null {
    const details = (application.offer_details ?? {}) as Record<string, unknown>;
    const raw = details.applicantSignature as Record<string, unknown> | undefined;
    const dataUrl = typeof raw?.dataUrl === 'string' ? raw.dataUrl : null;
    if (!dataUrl || !/^data:image\/(png|jpeg|jpg);base64,/i.test(dataUrl)) {
      return null;
    }
    const signedAt = typeof raw?.signedAt === 'string' ? raw.signedAt : undefined;
    return { dataUrl, signedAt };
  }

  /**
   * Bake the template's field overlays (labels, underlines, signature
   * placeholders, filled values) directly into the PDF bytes so the file
   * renders correctly anywhere — browser tab, OS PDF viewer, mobile mail
   * attachment — without relying on the frontend's react-pdf overlay layer.
   *
   * Field coordinates on the snapshot are stored as percentages of the page
   * dimensions with the origin at the top-left (matching react-pdf). pdf-lib
   * uses a bottom-left origin, so we flip Y when computing draw positions.
   * Signature values live in `value_text` as base64 data URLs (PNG); plain
   * text values live in the same column as the raw string.
   */
  private async renderPdfWithFieldOverlays(
    a: OfferLetterAssignment,
    opts: {
      applicantSignature?: { dataUrl: string; signedAt?: string } | null;
    } = {},
  ): Promise<{ buffer: Buffer; contentType: string; fileName: string }> {
    const snapshot = a.template_snapshot as unknown as TemplateSnapshot;
    if (!snapshot?.pdf_file_key) {
      throw new NotFoundException('Offer letter has no PDF attached');
    }

    const { buffer: templateBytes, contentType, fileName } =
      await this.templatesService.getPdfBuffer(a.organization_id, snapshot.id);

    // If the PDF can't be loaded (corrupt / not a PDF), fall back to the raw
    // bytes — the user at least gets the original document instead of an
    // error page.
    let pdfDoc: PDFDocument;
    try {
      pdfDoc = await PDFDocument.load(templateBytes);
    } catch (err) {
      this.logger.warn(
        `renderPdfWithFieldOverlays: failed to load template pdf, streaming raw bytes. ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      return { buffer: templateBytes, contentType, fileName };
    }

    const fields = Array.isArray(snapshot.document_fields)
      ? snapshot.document_fields
      : [];
    if (fields.length === 0) {
      return { buffer: templateBytes, contentType, fileName };
    }

    const valuesByFieldId = new Map<string, OfferLetterFieldValue>();
    for (const fv of a.fieldValues ?? []) {
      valuesByFieldId.set(fv.field_id, fv);
    }

    // Role-name lookup so the baked labels match the editor UI, which shows
    // "Signature (Employee)" / "Signature (Supervisor)" etc. A field's raw
    // `label` is often just "Signature"; the role name is part of the
    // contextual chrome the editor adds at display time.
    const roleNameById = new Map<string, string>();
    for (const role of snapshot.roles ?? []) {
      if (role?.id && typeof role.name === 'string') {
        roleNameById.set(role.id, role.name);
      }
    }

    // Identify the signature field the applicant's e-signature should land in.
    // Templates typically have "Signature (Employee)" and "Signature
    // (Supervisor)" fields — the applicant *is* the future employee, so
    // mapping their e-signature to the Employee signature field reads the
    // way HR expects on the rendered PDF instead of a floating box at the
    // page bottom. We match by role name (case-insensitive) against a
    // small allow-list, preferring `employee` first and falling back to
    // similar concepts.
    const APPLICANT_ROLE_ALIASES = ['employee', 'applicant', 'candidate', 'new hire'];
    const applicantTargetFieldId = (() => {
      if (!opts.applicantSignature?.dataUrl) return null;
      const isSignatureField = (f: TemplateFieldSnapshot): boolean => {
        const t = (f.type ?? '').toString().toLowerCase();
        if (t === 'signature') return true;
        // Fallback: some templates label the field "Signature" without the
        // explicit type set on the snapshot. Treat those as signature fields
        // too so older data still resolves.
        const label = (f.label ?? '').toString().toLowerCase();
        return label.startsWith('signature');
      };
      for (const alias of APPLICANT_ROLE_ALIASES) {
        const match = fields.find((f) => {
          if (!isSignatureField(f)) return false;
          const roleName = f.assignedRoleId
            ? (roleNameById.get(f.assignedRoleId) ?? '').toLowerCase().trim()
            : '';
          return roleName === alias;
        });
        if (match) return match.id;
      }
      return null;
    })();
    let applicantSignatureDrawn = false;

    const pages = pdfDoc.getPages();
    const helvetica = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const labelColor = rgb(0.58, 0.64, 0.72); // slate-400-ish
    const lineColor = rgb(0.28, 0.33, 0.41); // slate-700-ish
    const valueColor = rgb(0.06, 0.09, 0.16); // slate-900-ish

    for (const field of fields) {
      const pageIndex = Math.max(0, (field.page ?? 1) - 1);
      const page = pages[pageIndex];
      if (!page) continue;
      const pageWidth = page.getWidth();
      const pageHeight = page.getHeight();
      const xPct = field.xPct ?? 0;
      const yPct = field.yPct ?? 0;
      const wPct = field.wPct ?? 0;
      const hPct = field.hPct ?? 0;
      const boxX = xPct * pageWidth;
      const boxW = wPct * pageWidth;
      const boxH = hPct * pageHeight;
      // Flip Y: react-pdf draws from top, pdf-lib from bottom.
      const boxYTop = yPct * pageHeight;
      const boxBottomFromPdfOrigin = pageHeight - boxYTop - boxH;

      // Draw a thin underline along the bottom of the box — this is what the
      // user sees as "signature line" or "value line" in the template editor.
      page.drawLine({
        start: { x: boxX, y: boxBottomFromPdfOrigin },
        end: { x: boxX + boxW, y: boxBottomFromPdfOrigin },
        thickness: 0.75,
        color: lineColor,
      });

      // Label sits just below the line, small and muted. When a role owns
      // the field, append its name in parentheses (unless the label already
      // contains it) so "Signature (Employee)" reads the same way the editor
      // shows it.
      const rawLabel = (field.label ?? '').toString().trim();
      const roleName = field.assignedRoleId
        ? (roleNameById.get(field.assignedRoleId) ?? '').trim()
        : '';
      const labelText =
        roleName && !rawLabel.toLowerCase().includes(roleName.toLowerCase())
          ? rawLabel
            ? `${rawLabel} (${roleName})`
            : `(${roleName})`
          : rawLabel;
      if (labelText) {
        const labelSize = 7;
        page.drawText(labelText, {
          x: boxX,
          y: Math.max(0, boxBottomFromPdfOrigin - labelSize - 1),
          size: labelSize,
          font: helvetica,
          color: labelColor,
        });
      }

      // Fill the value, if any, above the underline.
      // Priority: the applicant's own e-signature goes in the employee /
      // applicant signature field when we identified one above. That wins
      // over any `fieldValues` row for the same field (e.g. an HR stand-in
      // signature left over from testing) — the applicant's signature is
      // the canonical "employee signed" value.
      const isApplicantTargetField =
        !!applicantTargetFieldId && field.id === applicantTargetFieldId;
      const applicantSigDataUrl = opts.applicantSignature?.dataUrl ?? null;
      if (isApplicantTargetField && applicantSigDataUrl) {
        try {
          const match = applicantSigDataUrl.match(
            /^data:image\/(png|jpeg|jpg);base64,(.+)$/i,
          );
          if (match) {
            const mime = match[1].toLowerCase();
            const imgBytes = Buffer.from(match[2], 'base64');
            const image =
              mime === 'png'
                ? await pdfDoc.embedPng(imgBytes)
                : await pdfDoc.embedJpg(imgBytes);
            const dims = image.scale(1);
            const scale = Math.min(boxW / dims.width, boxH / dims.height, 1);
            const drawW = dims.width * scale;
            const drawH = dims.height * scale;
            page.drawImage(image, {
              x: boxX,
              y: boxBottomFromPdfOrigin,
              width: drawW,
              height: drawH,
            });
            applicantSignatureDrawn = true;
            continue;
          }
        } catch (err) {
          this.logger.warn(
            `renderPdfWithFieldOverlays: failed to embed applicant signature in employee field. ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      }
      const fv = valuesByFieldId.get(field.id);
      if (!fv) continue;
      const text = typeof fv.value_text === 'string' ? fv.value_text : '';
      const isSignatureDataUrl = /^data:image\/(png|jpeg|jpg);base64,/i.test(text);

      if (isSignatureDataUrl) {
        try {
          const match = text.match(/^data:image\/(png|jpeg|jpg);base64,(.+)$/i);
          if (match) {
            const mime = match[1].toLowerCase();
            const b64 = match[2];
            const imgBytes = Buffer.from(b64, 'base64');
            const image = mime === 'png'
              ? await pdfDoc.embedPng(imgBytes)
              : await pdfDoc.embedJpg(imgBytes);
            // Fit the image inside the box while keeping aspect ratio.
            const dims = image.scale(1);
            const scale = Math.min(boxW / dims.width, boxH / dims.height, 1);
            const drawW = dims.width * scale;
            const drawH = dims.height * scale;
            page.drawImage(image, {
              x: boxX,
              y: boxBottomFromPdfOrigin,
              width: drawW,
              height: drawH,
            });
          }
        } catch (err) {
          this.logger.warn(
            `renderPdfWithFieldOverlays: failed to embed signature image. ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      } else if (text.trim()) {
        // Plain text / date / name — draw just above the line. Clip long
        // strings with an ellipsis so they never spill into neighbouring
        // fields; pdf-lib has no native clipping so we measure ourselves.
        const fontSize = Math.min(11, Math.max(8, boxH * 0.55));
        const displayed = this.truncateToWidth(
          text,
          boxW,
          fontSize,
          helvetica,
        );
        page.drawText(displayed, {
          x: boxX,
          y: boxBottomFromPdfOrigin + 1.5,
          size: fontSize,
          font: helvetica,
          color: valueColor,
        });
      }
    }

    // Applicant's e-signed signature (captured via the "Sign Offer Letter"
    // modal). Preferred placement was handled inside the field loop — their
    // signature drops into the Employee/Applicant-role signature field. If
    // no such field exists on the template, fall back to stamping the
    // signature at the bottom of the last page so it's still visible.
    const applicantSig = opts.applicantSignature;
    if (applicantSig?.dataUrl && pages.length > 0 && !applicantSignatureDrawn) {
      try {
        const match = applicantSig.dataUrl.match(
          /^data:image\/(png|jpeg|jpg);base64,(.+)$/i,
        );
        if (match) {
          const mime = match[1].toLowerCase();
          const imgBytes = Buffer.from(match[2], 'base64');
          const image =
            mime === 'png'
              ? await pdfDoc.embedPng(imgBytes)
              : await pdfDoc.embedJpg(imgBytes);
          const lastPage = pages[pages.length - 1];
          const pageWidth = lastPage.getWidth();
          const pageHeight = lastPage.getHeight();
          // Box sits in the left margin, 40pt above the page bottom, 40%
          // wide / 6% tall of the page — big enough to read, small enough
          // not to collide with other content.
          const margin = pageWidth * 0.08;
          const boxWidth = pageWidth * 0.4;
          const boxHeight = pageHeight * 0.06;
          const boxX = margin;
          const boxY = 40;
          const dims = image.scale(1);
          const scale = Math.min(
            boxWidth / dims.width,
            boxHeight / dims.height,
            1,
          );
          const drawW = dims.width * scale;
          const drawH = dims.height * scale;
          lastPage.drawLine({
            start: { x: boxX, y: boxY },
            end: { x: boxX + boxWidth, y: boxY },
            thickness: 0.75,
            color: lineColor,
          });
          lastPage.drawImage(image, {
            x: boxX,
            y: boxY,
            width: drawW,
            height: drawH,
          });
          const labelSuffix = applicantSig.signedAt
            ? ` — signed ${applicantSig.signedAt.slice(0, 10)}`
            : '';
          lastPage.drawText(`Applicant Signature${labelSuffix}`, {
            x: boxX,
            y: Math.max(0, boxY - 8),
            size: 7,
            font: helvetica,
            color: labelColor,
          });
        }
      } catch (err) {
        this.logger.warn(
          `renderPdfWithFieldOverlays: failed to embed applicant signature. ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }

    const bytes = await pdfDoc.save();
    return {
      buffer: Buffer.from(bytes),
      contentType,
      fileName,
    };
  }

  /**
   * Record the applicant's own signature (e-sign via canvas) on the offer
   * letter. Stored on `application.offer_details.applicantSignature` as a
   * base64 data URL + ISO timestamp. Later baked into the rendered PDF.
   */
  async saveApplicantSignature(
    userId: string,
    applicationId: string,
    signatureDataUrl: string,
    audit: {
      consentVersion: string;
      ip: string | null;
      userAgent: string | null;
      /** When the signature image was rendered from a typed name. */
      typedName?: string | null;
      /** Browser-reported geolocation at sign time. */
      geolocation?: {
        latitude: number;
        longitude: number;
        accuracy: number | null;
        capturedAt: string;
      } | null;
    },
  ): Promise<{ signedAt: string }> {
    if (!/^data:image\/(png|jpeg|jpg);base64,/i.test(signatureDataUrl)) {
      throw new BadRequestException(
        'signatureDataUrl must be a base64 image data URL (png or jpeg).',
      );
    }
    const consent = findApplicantOfferLetterConsent(audit.consentVersion);
    if (!consent) {
      throw new BadRequestException(
        `Unknown consent version "${audit.consentVersion}".`,
      );
    }
    const application = await this.assertApplicantOwnsApplication(userId, applicationId);
    const existing = (application.offer_details ?? {}) as Record<string, unknown>;
    // Enforce single-method response: if the applicant already uploaded a
    // signed copy they must clear it first before e-signing, so we never end
    // up with two "I accepted" artefacts that could disagree.
    const uploaded = existing.uploadedSignedOfferLetter as
      | Record<string, unknown>
      | undefined;
    if (uploaded && typeof uploaded.fileUrl === 'string' && uploaded.fileUrl) {
      throw new BadRequestException(
        'Remove your uploaded signed copy before e-signing the offer letter.',
      );
    }
    // Hash the template PDF bytes the applicant is signing. Stored with the
    // signature so we can later prove the document wasn't altered post-sign
    // (tamper detection for the ESIGN/UETA audit trail). Best-effort — a
    // missing/corrupt template shouldn't block the sign flow.
    const documentHash = await this.hashOfferLetterTemplate(existing).catch(
      (err) => {
        this.logger.warn(
          `saveApplicantSignature: could not hash template pdf. ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
        return null;
      },
    );
    const signedAt = new Date().toISOString();
    application.offer_details = {
      ...existing,
      applicantSignature: {
        dataUrl: signatureDataUrl,
        signedAt,
        consentVersion: consent.version,
        consentText: consent.text,
        ip: audit.ip,
        userAgent: audit.userAgent,
        documentHash,
        ...(audit.typedName ? { typedName: audit.typedName } : {}),
        ...(audit.geolocation ? { geolocation: audit.geolocation } : {}),
      },
    };
    await this.applicationRepo.save(application);
    return { signedAt };
  }

  /**
   * Compute a SHA-256 hex digest of the template PDF bytes referenced by
   * the offer letter assignment currently attached to the application.
   * Returns null when no assignment is attached. Used as part of the
   * e-signature audit trail (tamper detection).
   */
  private async hashOfferLetterTemplate(
    offerDetails: Record<string, unknown>,
  ): Promise<string | null> {
    const assignmentId =
      typeof offerDetails.offerLetterAssignmentId === 'string'
        ? offerDetails.offerLetterAssignmentId
        : null;
    if (!assignmentId) return null;
    const a = await this.assignmentRepo.findOne({ where: { id: assignmentId } });
    if (!a) return null;
    const { stream } = await this.streamSnapshotPdf(a);
    const buffer = await this.collectStreamToBuffer(stream);
    return createHash('sha256').update(buffer).digest('hex');
  }

  /**
   * Delete the applicant's e-signature so they can switch to uploading a
   * signed copy (or just clear it). Leaves the rest of `offer_details`
   * untouched — we don't want to wipe out HR-set fields like `salary`.
   */
  async clearApplicantSignature(
    userId: string,
    applicationId: string,
  ): Promise<void> {
    const application = await this.assertApplicantOwnsApplication(userId, applicationId);
    const existing = (application.offer_details ?? {}) as Record<string, unknown>;
    if (!existing.applicantSignature) return;
    const { applicantSignature: _removed, ...rest } = existing;
    application.offer_details = rest;
    await this.applicationRepo.save(application);
  }

  /**
   * Record an applicant-uploaded signed offer letter PDF. The file itself is
   * persisted via the shared job-application document storage; its public
   * URL + filename + upload timestamp live on
   * `application.offer_details.uploadedSignedOfferLetter`. The applicant can
   * later view/download their uploaded copy from the same place the org can.
   */
  async saveApplicantUploadedSignedOfferLetter(
    userId: string,
    applicationId: string,
    payload: { key: string; fileName: string },
  ): Promise<{ file_name: string; file_url: string; uploadedAt: string }> {
    const application = await this.assertApplicantOwnsApplication(userId, applicationId);
    const existing = (application.offer_details ?? {}) as Record<string, unknown>;
    // Mirror of saveApplicantSignature — only one response method at a time.
    const esig = existing.applicantSignature as Record<string, unknown> | undefined;
    if (esig && typeof esig.dataUrl === 'string' && esig.dataUrl) {
      throw new BadRequestException('Remove your e-signature before uploading a signed copy.');
    }
    const exists = await this.jobApplicationDocumentStorage.verifyUploaded(payload.key);
    if (!exists) {
      throw new BadRequestException('Uploaded file not found in storage. Retry the upload.');
    }
    const uploadedAt = new Date().toISOString();
    application.offer_details = {
      ...existing,
      uploadedSignedOfferLetter: {
        fileName: payload.fileName,
        fileUrl: payload.key,
        uploadedAt,
      },
    };
    await this.applicationRepo.save(application);
    return { file_name: payload.fileName, file_url: payload.key, uploadedAt };
  }

  /**
   * Delete the applicant's uploaded signed copy. Mirrors
   * `clearApplicantSignature` — lets them swap to e-signing.
   */
  async clearApplicantUploadedSignedOfferLetter(
    userId: string,
    applicationId: string,
  ): Promise<void> {
    const application = await this.assertApplicantOwnsApplication(userId, applicationId);
    const existing = (application.offer_details ?? {}) as Record<string, unknown>;
    if (!existing.uploadedSignedOfferLetter) return;
    const { uploadedSignedOfferLetter: _removed, ...rest } = existing;
    application.offer_details = rest;
    await this.applicationRepo.save(application);
  }

  /**
   * Resolve the auth'd user, load the application, and confirm the caller
   * owns it — either by `applicant_user_id` match (preferred) or falling
   * back to case-insensitive `applicant_email` match. Throws 403/404 as
   * appropriate.
   *
   * Both comparison keys are trimmed + lowercased: historically we've seen
   * mismatches caused by trailing whitespace on `applicant_email` from old
   * apply submissions. When the check fails we also opportunistically
   * backfill `applicant_user_id` if the email matches — so future reads
   * take the fast path even if nobody re-runs the signup backfill.
   */
  private async assertApplicantOwnsApplication(
    userId: string,
    applicationId: string,
  ): Promise<JobApplication> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user?.email) {
      throw new ForbiddenException('Unauthorized');
    }
    const application = await this.applicationRepo.findOne({
      where: { id: applicationId },
    });
    if (!application) throw new NotFoundException('Job application not found');
    const owns = this.applicantOwnsApplication(userId, user.email, application);
    if (!owns) {
      this.logger.warn(
        `Applicant ownership check failed: userId=${userId}, user.email=${this.redactEmail(user.email)}, ` +
          `applicant_user_id=${application.applicant_user_id ?? 'null'}, ` +
          `applicant_email=${this.redactEmail(application.applicant_email ?? '')}`,
      );
      throw new ForbiddenException(
        'You can only act on your own job application.',
      );
    }
    // Opportunistic backfill: we owned via email but the durable link was
    // missing. Fill it in so subsequent reads short-circuit at the first
    // branch without hitting email normalisation again.
    if (!application.applicant_user_id) {
      application.applicant_user_id = userId;
      try {
        await this.applicationRepo.save(application);
      } catch (err) {
        this.logger.warn(
          `Backfill of applicant_user_id failed (non-fatal): ${this.buildFailureMessage(err)}`,
        );
      }
    }
    return application;
  }

  /** Shared ownership predicate — trims + lowercases emails on both sides. */
  private applicantOwnsApplication(
    userId: string,
    userEmail: string,
    application: JobApplication,
  ): boolean {
    if (application.applicant_user_id && application.applicant_user_id === userId) {
      return true;
    }
    const userEmailNorm = userEmail.trim().toLowerCase();
    const applicantEmailNorm = application.applicant_email?.trim().toLowerCase();
    return (
      !!userEmailNorm &&
      !!applicantEmailNorm &&
      userEmailNorm === applicantEmailNorm
    );
  }

  /** HIPAA-safe email masking for log output — preserves diagnostic value without leaking PII. */
  private redactEmail(email: string): string {
    if (!email || !email.includes('@')) return email || '(empty)';
    const [local, domain] = email.split('@');
    if (!local) return `*@${domain}`;
    const shown = local.length > 1 ? `${local[0]}***` : `*`;
    return `${shown}@${domain}`;
  }

  /** Read a Node readable stream into a Buffer in memory. */
  private async collectStreamToBuffer(
    stream: NodeJS.ReadableStream,
  ): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of stream as AsyncIterable<Buffer | string>) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks);
  }

  /**
   * Trim `text` so it fits in `maxWidth` points at `fontSize`, appending an
   * ellipsis when it overflows. Uses pdf-lib's font width calculation; that's
   * the same font we draw with, so what we measure matches what's drawn.
   */
  private truncateToWidth(
    text: string,
    maxWidth: number,
    fontSize: number,
    font: Awaited<ReturnType<PDFDocument['embedFont']>>,
  ): string {
    if (font.widthOfTextAtSize(text, fontSize) <= maxWidth) return text;
    const ellipsis = '…';
    let lo = 0;
    let hi = text.length;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      const candidate = text.slice(0, mid) + ellipsis;
      if (font.widthOfTextAtSize(candidate, fontSize) <= maxWidth) lo = mid;
      else hi = mid - 1;
    }
    return text.slice(0, lo) + ellipsis;
  }

  /**
   * Stream the template PDF for the assignment backing a one-time fill token.
   * Used by `/v1/api/offer-letter/fill/:token/pdf` (no JWT required).
   */
  async getPdfByToken(
    token: string,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string; fileName: string }> {
    const roleAssignment = await this.roleRepo.findOne({
      where: { fill_token: token },
    });
    if (!roleAssignment) throw new NotFoundException('Invalid fill token');
    if (
      roleAssignment.fill_token_expires_at &&
      roleAssignment.fill_token_expires_at.getTime() < Date.now()
    ) {
      throw new ForbiddenException('Fill token has expired');
    }
    const a = await this.assignmentRepo.findOne({
      where: { id: roleAssignment.assignment_id },
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');
    return this.streamSnapshotPdf(a);
  }

  private async streamSnapshotPdf(
    a: OfferLetterAssignment,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string; fileName: string }> {
    const snapshot = a.template_snapshot as unknown as TemplateSnapshot;
    if (!snapshot?.pdf_file_key) {
      throw new NotFoundException('Offer letter has no PDF attached');
    }
    const { buffer, contentType, fileName } = await this.templatesService.getPdfBuffer(
      a.organization_id,
      snapshot.id,
    );
    const { Readable } = await import('stream');
    return { stream: Readable.from(buffer), contentType, fileName };
  }

  // ─── Writes ─────────────────────────────────────────────────────────────

  /**
   * Upsert one or more field values. The caller passes the role they are
   * filling under; we validate the user actually has that role on the
   * assignment (unless `bypassRoleCheck` is set by the token-gated flow).
   */
  async fillFields(
    assignmentId: string,
    fillerUserId: string,
    dto: FillOfferLetterFieldsDto,
    opts: {
      bypassRoleCheck?: boolean;
      requestMetadata?: { ip: string | null; userAgent: string | null };
    } = {},
  ): Promise<OfferLetterAssignment> {
    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['roleAssignments'],
    });
    if (!a) throw new NotFoundException('Offer letter assignment not found');

    if (!opts.bypassRoleCheck) {
      const authorized = a.roleAssignments.some(
        (r) => r.user_id === fillerUserId && r.role_id === dto.roleId,
      );
      if (!authorized) {
        throw new ForbiddenException(
          'You are not assigned to this role on this offer letter.',
        );
      }
    }

    const snapshotFields = this.snapshotFields(a);
    const editableFieldIds = new Set(
      snapshotFields
        .filter((f) => f.assignedRoleId === dto.roleId)
        .map((f) => f.id),
    );

    const unauthorizedFields = dto.fields
      .map((f) => f.fieldId)
      .filter((id) => !editableFieldIds.has(id));
    if (unauthorizedFields.length > 0) {
      throw new ForbiddenException(
        `Cannot write fields that belong to another role: ${unauthorizedFields.join(', ')}`,
      );
    }

    // Audit-trail gate: if any field being written is a signature or
    // initials, require an accepted consent version. Non-signature fields
    // (text, date, etc.) save without a consent check so the form still
    // works for casual edits.
    const isSignatureField = (fieldId: string): boolean => {
      const f = snapshotFields.find((x) => x.id === fieldId);
      if (!f) return false;
      const t = (f.type ?? '').toString().toLowerCase();
      if (t === 'signature' || t === 'initials') return true;
      const label = (f.label ?? '').toString().toLowerCase();
      return label.startsWith('signature') || label.startsWith('initials');
    };
    const touchesSignatureField = dto.fields.some((f) =>
      isSignatureField(f.fieldId),
    );
    let consent: { version: string; text: string } | null = null;
    let documentHash: string | null = null;
    if (touchesSignatureField) {
      if (dto.consentAccepted !== true) {
        throw new BadRequestException(
          'You must accept the electronic signature consent before signing.',
        );
      }
      const version = (dto.consentVersion ?? '').trim();
      if (!version) {
        throw new BadRequestException('consentVersion is required.');
      }
      const found = findRoleFillerOfferLetterConsent(version);
      if (!found) {
        throw new BadRequestException(
          `Unknown consent version "${version}".`,
        );
      }
      consent = { version: found.version, text: found.text };
      // Hash the template PDF bytes so we can later prove the document the
      // role-filler signed wasn't altered post-sign. Best-effort — a
      // missing/corrupt template shouldn't block the sign flow.
      try {
        const { stream } = await this.streamSnapshotPdf(a);
        const buffer = await this.collectStreamToBuffer(stream);
        documentHash = createHash('sha256').update(buffer).digest('hex');
      } catch (err) {
        this.logger.warn(
          `fillFields: could not hash template pdf. ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
    const requestIp = opts.requestMetadata?.ip ?? null;
    const requestUA = opts.requestMetadata?.userAgent ?? null;
    // Snapshot the signer's display name and title at sign time so the
    // SignedDocumentInfo block stays accurate even after the user later
    // changes their name / leaves the org / changes job title. The lookup
    // is best-effort: a missing user or missing org-staff row leaves the
    // corresponding field as null, never throws.
    const signerSnapshot = touchesSignatureField
      ? await this.resolveSignerSnapshot(fillerUserId, a.organization_id)
      : { name: null, title: null };
    const geolocationSnapshot = dto.geolocation
      ? {
          latitude: dto.geolocation.latitude,
          longitude: dto.geolocation.longitude,
          accuracy: dto.geolocation.accuracy ?? null,
          capturedAt: dto.geolocation.capturedAt ?? null,
        }
      : null;
    const buildSignatureAudit = (fieldId: string) => {
      if (!consent || !isSignatureField(fieldId)) return null;
      return {
        consentVersion: consent.version,
        consentText: consent.text,
        ip: requestIp,
        userAgent: requestUA,
        documentHash,
        signedAt: new Date().toISOString(),
        signerName: signerSnapshot.name,
        signerTitle: signerSnapshot.title,
        geolocation: geolocationSnapshot,
      };
    };

    for (const f of dto.fields) {
      const audit = buildSignatureAudit(f.fieldId);
      const existing = await this.valueRepo.findOne({
        where: { assignment_id: assignmentId, field_id: f.fieldId },
      });
      if (existing) {
        existing.value_text = f.valueText ?? null;
        existing.value_json = f.valueJson ?? null;
        existing.filled_by_user_id = fillerUserId;
        existing.filled_by_role_id = dto.roleId;
        if (audit) existing.signature_audit = audit;
        await this.valueRepo.save(existing);
      } else {
        await this.valueRepo.save(
          this.valueRepo.create({
            assignment_id: assignmentId,
            field_id: f.fieldId,
            value_text: f.valueText ?? null,
            value_json: f.valueJson ?? null,
            filled_by_user_id: fillerUserId,
            filled_by_role_id: dto.roleId,
            signature_audit: audit,
          }),
        );
      }
    }

    if (a.status === 'sent') {
      a.status = 'in_progress';
    }
    await this.assignmentRepo.save(a);

    await this.reconcileCompletion(assignmentId, dto.roleId, fillerUserId);
    const refreshed = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['roleAssignments', 'roleAssignments.role', 'fieldValues'],
    });
    const decorated = this.decorate(refreshed!);
    // Mirror `findForUser` and attach `myRoles` so the post-fill response has
    // the same shape as the initial-load response. Without this the frontend
    // loses the array of *all* of the caller's role rows on this assignment,
    // and any consumer using `myRoles` to compute "am I done?" gets a wrong
    // answer until the next full reload.
    const myRoles = decorated.roleAssignments.filter(
      (r) => r.user_id === fillerUserId,
    );
    return Object.assign(decorated, { myRoles });
  }

  /**
   * If every required field for a role has a value, mark that role's
   * assignment completed; if every role is complete, close the whole
   * assignment.
   */
  private async reconcileCompletion(
    assignmentId: string,
    roleId: string,
    userId: string,
  ): Promise<void> {
    const a = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
      relations: ['roleAssignments', 'fieldValues'],
    });
    if (!a) return;

    const snapshotFields = this.snapshotFields(a);
    const valueMap = new Map(a.fieldValues.map((v) => [v.field_id, v]));

    // A role is "done" when every field assigned to it has a non-empty value.
    // We intentionally do NOT exempt optional fields — otherwise a template
    // whose fields are all `required: false` would auto-complete the moment
    // any other role submits anything, flipping the whole assignment to
    // `completed` before this role's user has filled a single cell.
    const roleHasAllFields = (rid: string): boolean => {
      const roleFields = snapshotFields.filter((f) => f.assignedRoleId === rid);
      if (!roleFields.length) return true;
      return roleFields.every((f) => {
        const v = valueMap.get(f.id);
        if (!v) return false;
        // Match the frontend's "has value" semantics — empty strings and
        // empty JSON objects must NOT count as filled, otherwise a stale
        // empty fieldValue (left behind by a focus-and-blur or a prior
        // partial save) flips the role to completed after just one real sign.
        const hasText =
          typeof v.value_text === 'string' && v.value_text.trim() !== '';
        const hasJson =
          v.value_json != null &&
          typeof v.value_json === 'object' &&
          Object.keys(v.value_json as Record<string, unknown>).length > 0;
        return hasText || hasJson;
      });
    };

    if (roleHasAllFields(roleId)) {
      for (const ra of a.roleAssignments) {
        if (
          ra.role_id === roleId &&
          ra.user_id === userId &&
          !ra.completed_at
        ) {
          ra.completed_at = new Date();
          await this.roleRepo.save(ra);
        }
      }
    }

    const allRolesComplete = [
      ...new Set(
        snapshotFields
          .map((f) => f.assignedRoleId)
          .filter((x): x is string => !!x),
      ),
    ].every(roleHasAllFields);

    if (allRolesComplete) {
      if (a.status !== 'completed') {
        a.status = 'completed';
        a.completed_at = new Date();
        await this.assignmentRepo.save(a);
        // Fire-and-forget: archive the fully-signed PDF into the applicant's
        // HR File. The archive service is idempotent (deterministic S3 key
        // + existing-row check), so a re-fire is a no-op. Failures must
        // not block the completion transition itself, so we swallow + log.
        this.archiveService.archive(a.id).catch((err) => {
          this.logger.warn(
            `Offer letter archive failed for assignment ${a.id}: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        });
      }
    } else if (a.status === 'completed') {
      // Defensive: recover from an earlier premature-completion state.
      a.status = 'in_progress';
      a.completed_at = null;
      await this.assignmentRepo.save(a);
    }

    // Sequential-signing handoff: once the last internal row lands, hand
    // the offer off to the applicant. Self-guards against double-firing by
    // only running while the application is still `offer_pending`.
    await this.fireApplicantHandoffIfReady(a);
  }

  /**
   * If every internal (non-applicant) role row on an assignment is now
   * complete and the parent application is still parked in
   * `offer_pending`, transition the application to `offer_sent`, mark
   * `internalSigningComplete: true` on `offer_details`, and fire the
   * applicant-facing emails (review email + applicant role-fill emails
   * for any rows the applicant was pre-selected on).
   *
   * Idempotent — a re-entry (e.g. another field save after completion)
   * short-circuits at the status guard.
   */
  private async fireApplicantHandoffIfReady(
    assignment: OfferLetterAssignment,
  ): Promise<void> {
    if (!assignment.job_application_id) return;
    const application = await this.applicationRepo.findOne({
      where: { id: assignment.job_application_id },
      relations: ['job_posting'],
    });
    if (!application) return;
    if (application.status !== 'offer_pending') return;

    // Pull the freshest role rows — `assignment.roleAssignments` from the
    // caller may reflect pre-save state depending on where we were
    // invoked from.
    const latestRoles = await this.roleRepo.find({
      where: { assignment_id: assignment.id },
    });
    const { internalRows, applicantRows, userById } =
      await this.partitionRolesByApplicant(latestRoles, application);

    // Zero internal rows should have transitioned at create time — this is
    // defensive so a template edited after offer creation still advances.
    const allInternalDone =
      internalRows.length === 0 ||
      internalRows.every((r) => r.completed_at != null);
    if (!allInternalDone) return;

    const existingOfferDetails = (application.offer_details ?? {}) as Record<
      string,
      unknown
    >;
    application.status = 'offer_sent';
    application.offer_details = {
      ...existingOfferDetails,
      internalSigningComplete: true,
      internalSigningCompletedAt: new Date().toISOString(),
    };
    await this.applicationRepo.save(application);

    const templateName =
      (assignment.template_snapshot as unknown as { name?: string })?.name ??
      'Offer Letter';
    const report: OfferEmailDeliveryReport = {
      sent: 0,
      failed: 0,
      recipients: [],
    };
    try {
      await this.fireApplicantHandoff(
        application,
        templateName,
        applicantRows,
        userById,
        report,
      );
    } catch (err) {
      // Handoff email failures are non-fatal — status has already
      // transitioned, the applicant can still see the offer in-app. Log so
      // SMTP outages are visible in ops dashboards.
      this.logger.warn(
        `Applicant handoff email batch failed for assignment ${assignment.id}: ${this.buildFailureMessage(err)}`,
      );
    }
  }

  async void(orgId: string, id: string): Promise<OfferLetterAssignment> {
    const a = await this.findOne(orgId, id);
    a.status = 'voided';
    await this.assignmentRepo.save(a);
    return this.findOne(orgId, id);
  }

  async delete(orgId: string, id: string): Promise<void> {
    const a = await this.findOne(orgId, id);
    await this.assignmentRepo.remove(a);
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private snapshotFields(a: OfferLetterAssignment): TemplateFieldSnapshot[] {
    const snapshot = a.template_snapshot as unknown as TemplateSnapshot;
    return (snapshot?.document_fields ?? []) as TemplateFieldSnapshot[];
  }

  /**
   * Look up the signer's display name and best-available job title for the
   * SignedDocumentInfo audit block. Snapshotted into `signature_audit` at
   * sign time so the block keeps rendering correctly when the user later
   * changes their name, leaves the org, or gets a new title.
   *
   * Title resolution order:
   *   1. `OrganizationStaff.position_title` (org-scoped staff record)
   *   2. `OrganizationStaff.staffRole.name` (e.g. "Supervisor", "HR")
   *   3. `Employee.position_title` (org-scoped employee record)
   *   4. `null` — caller renders "—" so the layout stays stable.
   *
   * Best-effort: a missing user or missing membership row returns
   * `{ name: null, title: null }` and the audit row records null in the
   * matching JSON keys. The signing flow is never blocked on this lookup.
   */
  private async resolveSignerSnapshot(
    userId: string,
    organizationId: string | null,
  ): Promise<{ name: string | null; title: string | null }> {
    let name: string | null = null;
    let title: string | null = null;
    try {
      const user = await this.userRepo.findOne({ where: { id: userId } });
      if (user) {
        const composed = `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim();
        name = composed || user.email || null;
      }

      if (organizationId) {
        const staff = await this.orgStaffRepo.findOne({
          where: { user_id: userId, organization_id: organizationId },
          relations: ['staffRole'],
        });
        if (staff) {
          title = staff.position_title ?? staff.staffRole?.name ?? null;
        }

        if (!title) {
          const employee = await this.employeeRepo.findOne({
            where: { user_id: userId, organization_id: organizationId },
          });
          if (employee) {
            title = employee.position_title ?? null;
          }
        }
      }
    } catch (err) {
      this.logger.warn(
        `resolveSignerSnapshot failed for user=${userId} org=${organizationId}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    return { name, title };
  }

  /**
   * Attach `pdfUrl` (a presigned/proxied URL) to the snapshot so the frontend
   * can render the template PDF without extra plumbing.
   */
  private decorate(a: OfferLetterAssignment): OfferLetterAssignment {
    const snapshot = a.template_snapshot as unknown as TemplateSnapshot & {
      pdfUrl?: string;
    };
    if (snapshot?.pdf_file_key && snapshot.id) {
      snapshot.pdfUrl = this.templatesService.buildPdfUrl(
        a.organization_id,
        snapshot.id,
      );
      a.template_snapshot = snapshot as unknown as Record<string, unknown>;
    }
    return a;
  }
}
