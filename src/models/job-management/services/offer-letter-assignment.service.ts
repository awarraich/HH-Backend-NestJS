import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { randomBytes } from 'crypto';
import { OfferLetterAssignment } from '../entities/offer-letter-assignment.entity';
import {
  OfferLetterAssignmentRole,
  OfferRecipientType,
} from '../entities/offer-letter-assignment-role.entity';
import { OfferLetterFieldValue } from '../entities/offer-letter-field-value.entity';
import { CompetencyTemplate } from '../../organizations/document-workflow/entities/competency-template.entity';
import { DocumentWorkflowRole } from '../../organizations/document-workflow/entities/document-workflow-role.entity';
import { JobApplication } from '../entities/job-application.entity';
import { User } from '../../../authentication/entities/user.entity';
import {
  CreateOfferLetterAssignmentDto,
  OfferRoleAssigneeDto,
} from '../dto/create-offer-letter-assignment.dto';
import { FillOfferLetterFieldsDto } from '../dto/fill-offer-letter-fields.dto';
import { TemplatesService } from '../../organizations/document-workflow/services/templates.service';
import { EmailService } from '../../../common/services/email/email.service';

const FILL_TOKEN_TTL_DAYS = 30;

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
    private readonly templatesService: TemplatesService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
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

    // Persist offer metadata on the job application so downstream views (e.g.
    // SignedOfferViewerModal, status badges) continue to work.
    if (dto.offerDetails) {
      const existing = (application.offer_details ?? {}) as Record<string, unknown>;
      application.offer_details = {
        ...existing,
        ...dto.offerDetails,
        templateId: template.id,
        templateName: template.name,
        offerLetterAssignmentId: assignment.id,
        sentAt: new Date().toISOString(),
      };
      if (application.status === 'pending' || application.status === 'interview') {
        application.status = 'offer_pending';
      }
      await this.applicationRepo.save(application);
    }

    await this.notifyAssignees(application, template.name, savedRoles);

    return this.findOne(orgId, assignment.id);
  }

  /**
   * Send one email per assignee. Each recipient gets a link appropriate to
   * their role: internal staff/employees land on an in-app view, external
   * employees get a token-gated public URL.
   */
  private async notifyAssignees(
    application: JobApplication,
    templateName: string,
    roleRows: OfferLetterAssignmentRole[],
  ): Promise<void> {
    if (!roleRows.length) return;

    const frontendBase = (
      this.configService.get<string>('HOME_HEALTH_AI_URL') ?? ''
    ).replace(/\/$/, '');

    const userIds = [...new Set(roleRows.map((r) => r.user_id))];
    const users = userIds.length
      ? await this.userRepo.find({ where: { id: In(userIds) } })
      : [];
    const userById = new Map(users.map((u) => [u.id, u]));

    const offerDetails = (application.offer_details ?? {}) as Record<string, unknown>;

    for (const row of roleRows) {
      const user = userById.get(row.user_id);
      if (!user?.email) continue;

      const fillUrl = this.buildFillUrl(frontendBase, row);
      const recipientName = this.fullName(user) || application.applicant_name || 'there';

      try {
        await this.emailService.sendOfferLetterEmail(user.email, {
          applicantName: recipientName,
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
          fillUrl,
          recipientType: row.recipient_type,
        });
      } catch (err) {
        this.logger.warn(
          `Offer letter email to user ${row.user_id} failed: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
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
    return assignments.map((a) => {
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
    return this.templatesService.getPdfStream(a.organization_id, snapshot.id);
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
    opts: { bypassRoleCheck?: boolean } = {},
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

    for (const f of dto.fields) {
      const existing = await this.valueRepo.findOne({
        where: { assignment_id: assignmentId, field_id: f.fieldId },
      });
      if (existing) {
        existing.value_text = f.valueText ?? null;
        existing.value_json = f.valueJson ?? null;
        existing.filled_by_user_id = fillerUserId;
        existing.filled_by_role_id = dto.roleId;
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
    return this.decorate(refreshed!);
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
        return !!v && (v.value_text != null || v.value_json != null);
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
      }
    } else if (a.status === 'completed') {
      // Defensive: recover from an earlier premature-completion state.
      a.status = 'in_progress';
      a.completed_at = null;
      await this.assignmentRepo.save(a);
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
