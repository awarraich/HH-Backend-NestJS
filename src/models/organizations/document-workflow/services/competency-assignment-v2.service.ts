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

import { CompetencyAssignment } from '../entities/competency-assignment.entity';
import {
  CompetencyAssignmentRole,
  CompetencyRecipientType,
} from '../entities/competency-assignment-role.entity';
import { CompetencyAssignmentFieldValue } from '../entities/competency-assignment-field-value.entity';
import { CompetencyTemplate } from '../entities/competency-template.entity';
import { DocumentWorkflowRole } from '../entities/document-workflow-role.entity';
import { User } from '../../../../authentication/entities/user.entity';
import { Organization } from '../../entities/organization.entity';
import { OrganizationCompanyProfileService } from '../../company-profile-setup/services/organization-company-profile.service';
import { OrganizationStaff } from '../../staff-management/entities/organization-staff.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { EmailService } from '../../../../common/services/email/email.service';
import { TemplatesService } from './templates.service';
import {
  CompetencyAssigneeDto,
  CreateCompetencyAssignmentV2Dto,
} from '../dto/create-competency-assignment-v2.dto';
import {
  FillCompetencyFieldsByTokenDto,
  FillCompetencyFieldsV2Dto,
} from '../dto/fill-competency-fields-v2.dto';
import { findCompetencyRoleFillerConsent } from '../constants/esign-consent';

const FILL_TOKEN_TTL_DAYS = 30;

interface TemplateFieldSnapshot {
  id: string;
  type?: string;
  label?: string;
  assignedRoleId?: string | null;
  required?: boolean;
  [k: string]: unknown;
}

interface TemplateSnapshot {
  id: string;
  name: string;
  description?: string;
  roles: Array<{ id: string; name: string; color?: string; order?: number }>;
  document_fields: TemplateFieldSnapshot[];
  pdf_file_key?: string | null;
  pdf_original_name?: string | null;
}

export interface CompetencyEmailRecipientResult {
  email: string | null;
  status: 'sent' | 'failed' | 'skipped';
  reason?: string;
}

export interface CompetencyEmailDeliveryReport {
  sent: number;
  failed: number;
  skipped: number;
  recipients: CompetencyEmailRecipientResult[];
}

/**
 * Decorated assignment shape returned by `findForUser` / fill / submit.
 * Carries `myRoles` (the caller's role rows on the instance) and a per-field
 * `isEditable` precomputed for the active role so the frontend doesn't have
 * to re-derive it from the snapshot.
 */
export type DecoratedCompetencyAssignment = CompetencyAssignment & {
  roleAssignments: CompetencyAssignmentRole[];
  fieldValues: CompetencyAssignmentFieldValue[];
  myRoles: CompetencyAssignmentRole[];
  /** Convenience: the role-row currently being filled (one entry per row,
   *  per the 1-per-role policy — callers iterate `myRoles` to render one
   *  filler card per row). */
  activeRoleId?: string | null;
  template_snapshot: TemplateSnapshot;
};

@Injectable()
export class CompetencyAssignmentV2Service {
  private readonly logger = new Logger(CompetencyAssignmentV2Service.name);

  constructor(
    @InjectRepository(CompetencyAssignment)
    private readonly assignmentRepo: Repository<CompetencyAssignment>,
    @InjectRepository(CompetencyAssignmentRole)
    private readonly roleRepo: Repository<CompetencyAssignmentRole>,
    @InjectRepository(CompetencyAssignmentFieldValue)
    private readonly valueRepo: Repository<CompetencyAssignmentFieldValue>,
    @InjectRepository(CompetencyTemplate)
    private readonly templateRepo: Repository<CompetencyTemplate>,
    @InjectRepository(DocumentWorkflowRole)
    private readonly workflowRoleRepo: Repository<DocumentWorkflowRole>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(Organization)
    private readonly organizationRepo: Repository<Organization>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaffRepo: Repository<OrganizationStaff>,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly companyProfileService: OrganizationCompanyProfileService,
    private readonly templatesService: TemplatesService,
  ) {}

  // ── Create ──────────────────────────────────────────────────────────────

  async create(
    orgId: string,
    dto: CreateCompetencyAssignmentV2Dto,
    createdByUserId: string,
  ): Promise<{
    assignment: DecoratedCompetencyAssignment;
    email_delivery: CompetencyEmailDeliveryReport;
  }> {
    const template = await this.templateRepo.findOne({
      where: { id: dto.templateId, organization_id: orgId },
    });
    if (!template) throw new NotFoundException('Template not found');

    const employee = await this.userRepo.findOne({
      where: { id: dto.employeeUserId },
    });
    if (!employee) throw new NotFoundException('Employee user not found');

    if (!Array.isArray(dto.assignees) || dto.assignees.length === 0) {
      throw new BadRequestException('At least one role assignee is required.');
    }

    // Every role used by a field must be covered by ≥1 assignee.
    const fields = (template.document_fields ?? []) as TemplateFieldSnapshot[];
    const rolesUsedInFields = new Set<string>(
      fields
        .map((f) => f.assignedRoleId)
        .filter((x): x is string => typeof x === 'string' && !!x),
    );
    const assigneeRoleIds = [...new Set(dto.assignees.map((a) => a.roleId))];
    const missing = [...rolesUsedInFields].filter(
      (rid) => !assigneeRoleIds.includes(rid),
    );
    if (missing.length > 0) {
      const templateRoles = (template.roles ?? []) as Array<{
        id: string;
        name?: string;
      }>;
      const missingNames = missing.map(
        (id) => templateRoles.find((r) => r.id === id)?.name ?? id,
      );
      throw new BadRequestException(
        `Every template role used by a field must have at least one assignee. Missing: ${missingNames.join(', ')}`,
      );
    }

    // All referenced role IDs must exist on the workflow_roles table.
    const dbRoles = await this.workflowRoleRepo
      .createQueryBuilder('r')
      .where('r.id IN (:...ids)', { ids: assigneeRoleIds })
      .andWhere('(r.organization_id = :orgId OR r.is_default = true)', {
        orgId,
      })
      .getMany();
    if (dbRoles.length !== assigneeRoleIds.length) {
      throw new BadRequestException('One or more role IDs are invalid.');
    }

    const snapshot: TemplateSnapshot = {
      id: template.id,
      name: template.name,
      description: template.description,
      roles: (template.roles ?? []) as TemplateSnapshot['roles'],
      document_fields: fields,
      pdf_file_key: template.pdf_file_key,
      pdf_original_name: template.pdf_original_name,
    };

    // Re-assigning the same template to the same employee should give them a
    // fresh slate, not a duplicate card alongside the prior one. Void every
    // still-open assignment for (org, template) that targets this employee,
    // matched two ways:
    //   - v2 rows: `employee_user_id` matches.
    //   - legacy rows from before v2: linked to the employee via
    //     `document_template_user_assignments(template_id, user_id)`.
    // Completed rows are kept so HR's audit trail survives — the user just
    // stops seeing them in their "to fill" inbox via the voided filter on
    // `findForUser` / `getForEmployee`.
    await this.assignmentRepo.manager.query(
      `UPDATE competency_assignments
         SET status = 'voided'
         WHERE organization_id = $1
           AND template_id = $2
           AND status IN ('sent', 'in_progress')
           AND (
             employee_user_id = $3
             OR EXISTS (
               SELECT 1 FROM document_template_user_assignments dtua
                WHERE dtua.template_id = competency_assignments.template_id
                  AND dtua.user_id = $3
             )
           )`,
      [orgId, template.id, dto.employeeUserId],
    );

    const assignment = await this.assignmentRepo.save(
      this.assignmentRepo.create({
        organization_id: orgId,
        template_id: template.id,
        template_snapshot: snapshot as unknown as Record<string, unknown>,
        name: template.name || 'Untitled',
        // Reuse the existing supervisor_id column to record the first
        // non-employee assignee — keeps the legacy single-supervisor
        // listings (HR-File detail's existing roleFillerAssignments query)
        // populated until they migrate to v2.
        supervisor_id:
          dto.assignees.find((a) => a.recipientType !== 'employee')?.userId ??
          dto.assignees[0]!.userId,
        employee_user_id: dto.employeeUserId,
        status: 'sent',
        created_by: createdByUserId,
      }),
    );

    // Persist role rows (with fill_token for external recipients).
    const roleRows: CompetencyAssignmentRole[] = [];
    for (const a of dto.assignees) {
      roleRows.push(this.buildRoleRow(assignment.id, a));
    }
    await this.roleRepo.save(roleRows);

    const email_delivery = await this.notifyAssignees(
      orgId,
      assignment.id,
      template,
      employee,
      roleRows,
    );

    const decorated = await this.findOneByIdInternal(assignment.id);
    return { assignment: decorated, email_delivery };
  }

  private buildRoleRow(
    assignmentId: string,
    a: CompetencyAssigneeDto,
  ): CompetencyAssignmentRole {
    const row = this.roleRepo.create({
      assignment_id: assignmentId,
      role_id: a.roleId,
      user_id: a.userId,
      recipient_type: a.recipientType as CompetencyRecipientType,
      status: 'pending',
    });
    if (a.recipientType === 'external_employee') {
      row.fill_token = randomBytes(48).toString('base64url');
      const expires = new Date();
      expires.setDate(expires.getDate() + FILL_TOKEN_TTL_DAYS);
      row.fill_token_expires_at = expires;
    }
    return row;
  }

  // ── Email fan-out ───────────────────────────────────────────────────────

  private async notifyAssignees(
    orgId: string,
    assignmentId: string,
    template: CompetencyTemplate,
    employee: User,
    roleRows: CompetencyAssignmentRole[],
  ): Promise<CompetencyEmailDeliveryReport> {
    const report: CompetencyEmailDeliveryReport = {
      sent: 0,
      failed: 0,
      skipped: 0,
      recipients: [],
    };
    if (!roleRows.length) return report;

    const frontendBase = (
      this.configService.get<string>('HOME_HEALTH_AI_URL') ?? ''
    ).replace(/\/$/, '');

    const userIds = [...new Set(roleRows.map((r) => r.user_id))];
    const users = await this.userRepo.find({ where: { id: In(userIds) } });
    const userById = new Map(users.map((u) => [u.id, u]));

    const roleIds = [...new Set(roleRows.map((r) => r.role_id))];
    const roles = await this.workflowRoleRepo.find({
      where: { id: In(roleIds) },
    });
    const roleNameById = new Map(roles.map((r) => [r.id, r.name]));

    const [organizationName, orgLogo] = await Promise.all([
      this.resolveOrganizationName(orgId),
      this.companyProfileService.getOrganizationLogoBytes(orgId),
    ]);

    const employeeName = this.fullName(employee) || employee.email || '';

    for (const row of roleRows) {
      const user = userById.get(row.user_id);
      if (!user?.email) {
        report.skipped += 1;
        report.recipients.push({
          email: null,
          status: 'skipped',
          reason: 'No email on file for this assignee.',
        });
        continue;
      }
      const fillUrl = this.buildFillUrl(frontendBase, assignmentId, row);
      const recipientName = this.fullName(user) || user.email || 'there';
      try {
        await this.emailService.sendCompetencyFillEmail(
          user.email,
          {
            recipientName,
            employeeName,
            roleName: roleNameById.get(row.role_id) ?? 'Signer',
            templateName: template.name || 'Competency Document',
            templateDescription: template.description ?? undefined,
            organizationName,
            fillUrl,
            recipientType: row.recipient_type,
          },
          orgLogo,
        );
        report.sent += 1;
        report.recipients.push({ email: user.email, status: 'sent' });
      } catch (err) {
        report.failed += 1;
        const reason = err instanceof Error ? err.message : String(err);
        this.logger.warn(
          `Competency fill email to user ${row.user_id} (${user.email}) failed: ${reason}`,
        );
        report.recipients.push({
          email: user.email,
          status: 'failed',
          reason,
        });
      }
    }

    return report;
  }

  private buildFillUrl(
    frontendBase: string,
    assignmentId: string,
    row: CompetencyAssignmentRole,
  ): string {
    if (row.recipient_type === 'external_employee' && row.fill_token) {
      return `${frontendBase}/competency/fill/${row.fill_token}`;
    }
    const target =
      row.recipient_type === 'employee'
        ? `/employee/competency?assignment=${assignmentId}`
        : `/organization/document-workflow?assignment=${assignmentId}`;
    return `${frontendBase}/competency/open?to=${encodeURIComponent(target)}`;
  }

  private fullName(user: User): string {
    const first = (user as unknown as { firstName?: string }).firstName ?? '';
    const last = (user as unknown as { lastName?: string }).lastName ?? '';
    return `${first} ${last}`.trim();
  }

  private async resolveOrganizationName(
    organizationId: string,
  ): Promise<string | undefined> {
    const org = await this.organizationRepo.findOne({
      where: { id: organizationId },
      select: ['id', 'organization_name'],
    });
    return org?.organization_name?.trim() || undefined;
  }

  // ── Reads ───────────────────────────────────────────────────────────────

  /** Internal — returns a fully decorated row by id, no ownership check. */
  private async findOneByIdInternal(
    id: string,
  ): Promise<DecoratedCompetencyAssignment> {
    const a = await this.assignmentRepo
      .createQueryBuilder('a')
      .where('a.id = :id', { id })
      .getOne();
    if (!a) throw new NotFoundException('Assignment not found');
    const [roleAssignments, fieldValues] = await Promise.all([
      this.roleRepo.find({
        where: { assignment_id: id },
        relations: ['role'],
        order: { created_at: 'ASC' },
      }),
      this.valueRepo.find({ where: { assignment_id: id } }),
    ]);
    const snapshot = a.template_snapshot as unknown as TemplateSnapshot & {
      pdfUrl?: string;
    };
    // Default to the existing JWT-only template view URL — every authenticated
    // role-filler can hit it (`@Roles()` on the route admits any auth'd user).
    // The token-gated controller overrides this with the public `/competency/
    // fill/:token/pdf` URL before responding so external employees don't
    // need a JWT.
    if (snapshot.pdf_file_key) {
      snapshot.pdfUrl = `/v1/api/organizations/${a.organization_id}/document-workflow/templates/${snapshot.id}/pdf/view`;
    }
    return Object.assign(a, {
      roleAssignments,
      fieldValues,
      myRoles: [] as CompetencyAssignmentRole[],
      template_snapshot: snapshot,
    }) as DecoratedCompetencyAssignment;
  }

  /** Org-admin scoped read by id. */
  async findOneForOrg(
    orgId: string,
    id: string,
  ): Promise<DecoratedCompetencyAssignment> {
    const a = await this.assignmentRepo.findOne({
      where: { id, organization_id: orgId },
    });
    if (!a) throw new NotFoundException('Assignment not found');
    return this.findOneByIdInternal(id);
  }

  /** Org-admin: list v2 assignments for an employee (voided rows hidden). */
  async findForEmployee(
    orgId: string,
    employeeUserId: string,
  ): Promise<DecoratedCompetencyAssignment[]> {
    const rows = await this.assignmentRepo.find({
      where: { organization_id: orgId, employee_user_id: employeeUserId },
      order: { created_at: 'DESC' },
    });
    if (!rows.length) return [];
    const live = rows.filter((a) => a.status !== 'voided');
    return Promise.all(live.map((a) => this.findOneByIdInternal(a.id)));
  }

  /**
   * Self-scoped: return one entry per (assignment, role) the caller holds —
   * matches the 1-per-role policy. Voided assignments are filtered out so a
   * re-assignment of the same template doesn't keep showing the prior row's
   * stale data alongside the fresh one.
   */
  async findForUser(
    userId: string,
  ): Promise<DecoratedCompetencyAssignment[]> {
    const rows = await this.roleRepo.find({
      where: { user_id: userId },
      order: { created_at: 'DESC' },
    });
    if (!rows.length) return [];
    const assignmentIds = [...new Set(rows.map((r) => r.assignment_id))];
    const assignments = await this.assignmentRepo.find({
      where: { id: In(assignmentIds) },
      order: { created_at: 'DESC' },
    });
    const liveAssignmentIds = new Set(
      assignments.filter((a) => a.status !== 'voided').map((a) => a.id),
    );
    const decoratedById = new Map<string, DecoratedCompetencyAssignment>();
    for (const a of assignments) {
      if (a.status === 'voided') continue;
      decoratedById.set(a.id, await this.findOneByIdInternal(a.id));
    }
    // Emit one card per role row — duplicate the assignment object so the
    // frontend can render a per-role list. Skip role rows whose parent
    // assignment was voided (e.g., HR re-assigned the same template).
    const out: DecoratedCompetencyAssignment[] = [];
    for (const r of rows) {
      if (!liveAssignmentIds.has(r.assignment_id)) continue;
      const decorated = decoratedById.get(r.assignment_id);
      if (!decorated) continue;
      const myRoles = decorated.roleAssignments.filter(
        (x) => x.user_id === userId && x.role_id === r.role_id,
      );
      out.push({
        ...decorated,
        myRoles,
        activeRoleId: r.role_id,
      });
    }
    return out;
  }

  /**
   * Self-scoped read for a single assignment+role. Returns the decorated
   * shape with `myRoles` filtered to the caller and `activeRoleId` set
   * when supplied; ownership is enforced (caller must hold that role row).
   */
  async findOneForUser(
    id: string,
    userId: string,
    activeRoleId?: string,
  ): Promise<DecoratedCompetencyAssignment> {
    const decorated = await this.findOneByIdInternal(id);
    if (decorated.status === 'voided') {
      throw new NotFoundException('Assignment not found');
    }
    const allUserRoles = decorated.roleAssignments.filter(
      (r) => r.user_id === userId,
    );
    if (!allUserRoles.length) {
      throw new ForbiddenException('You are not assigned to this workflow.');
    }
    const resolvedActiveRole =
      activeRoleId ?? allUserRoles[0]!.role_id;
    if (!allUserRoles.some((r) => r.role_id === resolvedActiveRole)) {
      throw new ForbiddenException('You do not hold that role on this workflow.');
    }
    // Per the per-role-card shape produced by `findForUser`, narrow myRoles
    // to just the active role row so the frontend always renders the right
    // status without having to disambiguate `myRoles[0]`.
    const myRoles = allUserRoles.filter(
      (r) => r.role_id === resolvedActiveRole,
    );
    return {
      ...decorated,
      myRoles,
      activeRoleId: resolvedActiveRole,
    };
  }

  async findByFillToken(token: string): Promise<{
    assignment: DecoratedCompetencyAssignment;
    roleAssignment: CompetencyAssignmentRole;
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
      throw new ForbiddenException('Fill token has expired.');
    }
    const decorated = await this.findOneByIdInternal(
      roleAssignment.assignment_id,
    );
    // Public caller has no JWT — rewrite the snapshot pdfUrl to the
    // token-gated stream so the in-browser viewer can fetch bytes.
    const snapshot = decorated.template_snapshot as TemplateSnapshot & {
      pdfUrl?: string;
    };
    if (snapshot.pdf_file_key) {
      snapshot.pdfUrl = `/v1/api/competency/fill/${token}/pdf`;
    }
    return {
      assignment: {
        ...decorated,
        template_snapshot: snapshot,
        myRoles: [roleAssignment],
        activeRoleId: roleAssignment.role_id,
      },
      roleAssignment,
    };
  }

  /**
   * Stream the template PDF for a token-gated competency fill page. Reuses
   * the existing `TemplatesService.getPdfBuffer` via the org id stored on
   * the assignment row.
   */
  async getPdfByToken(
    token: string,
  ): Promise<{ buffer: Buffer; contentType: string; fileName: string }> {
    const roleAssignment = await this.roleRepo.findOne({
      where: { fill_token: token },
    });
    if (!roleAssignment) throw new NotFoundException('Invalid fill token');
    if (
      roleAssignment.fill_token_expires_at &&
      roleAssignment.fill_token_expires_at.getTime() < Date.now()
    ) {
      throw new ForbiddenException('Fill token has expired.');
    }
    const a = await this.assignmentRepo.findOne({
      where: { id: roleAssignment.assignment_id },
    });
    if (!a) throw new NotFoundException('Assignment not found');
    const snapshot = a.template_snapshot as unknown as TemplateSnapshot;
    if (!snapshot?.pdf_file_key) {
      throw new NotFoundException('Template has no PDF attached.');
    }
    return this.templatesService.getPdfBuffer(a.organization_id, snapshot.id);
  }

  // ── Fill ────────────────────────────────────────────────────────────────

  async fillFields(
    assignmentId: string,
    fillerUserId: string,
    dto: FillCompetencyFieldsV2Dto,
    opts: {
      bypassMembershipCheck?: boolean;
      requestMetadata?: { ip: string | null; userAgent: string | null };
    } = {},
  ): Promise<DecoratedCompetencyAssignment> {
    const assignment = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
    });
    if (!assignment) throw new NotFoundException('Assignment not found');

    const roleRow = await this.roleRepo.findOne({
      where: {
        assignment_id: assignmentId,
        role_id: dto.roleId,
        ...(opts.bypassMembershipCheck ? {} : { user_id: fillerUserId }),
      },
    });
    if (!roleRow) {
      throw new ForbiddenException(
        'You are not assigned to this role on this workflow.',
      );
    }

    const snapshot = assignment.template_snapshot as unknown as TemplateSnapshot;
    const fields = (snapshot.document_fields ?? []) as TemplateFieldSnapshot[];
    const editableFieldIds = new Set(
      fields
        .filter((f) => f.assignedRoleId === dto.roleId)
        .map((f) => f.id),
    );

    const unauthorized = dto.fields
      .map((f) => f.fieldId)
      .filter((id) => !editableFieldIds.has(id));
    if (unauthorized.length > 0) {
      throw new ForbiddenException(
        `Cannot write fields that belong to another role: ${unauthorized.join(', ')}`,
      );
    }

    // E-signature consent gate — required when any field touched is a
    // signature/initials field.
    const isSignatureField = (fieldId: string): boolean => {
      const f = fields.find((x) => x.id === fieldId);
      if (!f) return false;
      const t = String(f.type ?? '').toLowerCase();
      if (t === 'signature' || t === 'initials') return true;
      const label = String(f.label ?? '').toLowerCase();
      return label.startsWith('signature') || label.startsWith('initials');
    };
    const touchesSignatureField = dto.fields.some((f) =>
      isSignatureField(f.fieldId),
    );
    let consent: { version: string; text: string } | null = null;
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
      const found = findCompetencyRoleFillerConsent(version);
      if (!found) {
        throw new BadRequestException(
          `Unknown consent version "${version}".`,
        );
      }
      consent = { version: found.version, text: found.text };
    }

    const requestIp = opts.requestMetadata?.ip ?? null;
    const requestUA = opts.requestMetadata?.userAgent ?? null;
    const signerSnapshot = touchesSignatureField
      ? await this.resolveSignerSnapshot(fillerUserId, assignment.organization_id)
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

    // Per-role status: any save flips pending → in_progress; if the role
    // was previously submitted, re-saving "re-opens" it (per spec: role
    // holders can edit again after submitting).
    if (roleRow.status === 'pending') {
      roleRow.status = 'in_progress';
      await this.roleRepo.save(roleRow);
    } else if (roleRow.status === 'submitted') {
      roleRow.status = 'in_progress';
      roleRow.submitted_at = null;
      await this.roleRepo.save(roleRow);
    }
    if (assignment.status === 'sent') {
      assignment.status = 'in_progress';
      await this.assignmentRepo.save(assignment);
    } else if (assignment.status === 'completed') {
      // A re-edit after completion drops the instance back to in_progress
      // until the role re-submits.
      assignment.status = 'in_progress';
      assignment.completed_at = null;
      await this.assignmentRepo.save(assignment);
    }

    return this.findOneForToken(assignmentId, fillerUserId, dto.roleId, opts.bypassMembershipCheck);
  }

  /**
   * Mark a role row as `submitted`. Re-runs reconciliation so the parent
   * instance flips to `completed` once every role is submitted.
   */
  async submitRole(
    assignmentId: string,
    fillerUserId: string,
    roleId: string,
    opts: { bypassMembershipCheck?: boolean } = {},
  ): Promise<DecoratedCompetencyAssignment> {
    const roleRow = await this.roleRepo.findOne({
      where: {
        assignment_id: assignmentId,
        role_id: roleId,
        ...(opts.bypassMembershipCheck ? {} : { user_id: fillerUserId }),
      },
    });
    if (!roleRow) {
      throw new ForbiddenException(
        'You are not assigned to this role on this workflow.',
      );
    }
    roleRow.status = 'submitted';
    roleRow.submitted_at = new Date();
    await this.roleRepo.save(roleRow);
    await this.reconcileCompletion(assignmentId);
    return this.findOneForToken(assignmentId, fillerUserId, roleId, opts.bypassMembershipCheck);
  }

  private async findOneForToken(
    assignmentId: string,
    fillerUserId: string,
    roleId: string,
    bypassMembershipCheck?: boolean,
  ): Promise<DecoratedCompetencyAssignment> {
    const decorated = await this.findOneByIdInternal(assignmentId);
    // Filter myRoles to JUST the row being acted on, regardless of auth path.
    // Matches the per-role-card shape produced by `findForUser` so the
    // frontend slice's `replaceMine` always swaps the correct card and
    // `myRoles[0]` always reflects the role whose status just changed.
    const myRoles = bypassMembershipCheck
      ? decorated.roleAssignments.filter((r) => r.role_id === roleId)
      : decorated.roleAssignments.filter(
          (r) => r.user_id === fillerUserId && r.role_id === roleId,
        );
    return { ...decorated, myRoles, activeRoleId: roleId };
  }

  /**
   * Aggregate instance status:
   *   - all roles `submitted` → instance `completed`
   *   - any role `in_progress` or `submitted` → instance `in_progress`
   *   - all roles `pending` → instance `sent`
   * Roles that own no fields are treated as "auto-complete" (no work to do).
   */
  private async reconcileCompletion(assignmentId: string): Promise<void> {
    const assignment = await this.assignmentRepo.findOne({
      where: { id: assignmentId },
    });
    if (!assignment) return;
    const [roles, values] = await Promise.all([
      this.roleRepo.find({ where: { assignment_id: assignmentId } }),
      this.valueRepo.find({ where: { assignment_id: assignmentId } }),
    ]);
    const snapshot =
      assignment.template_snapshot as unknown as TemplateSnapshot;
    const fields = (snapshot.document_fields ?? []) as TemplateFieldSnapshot[];

    const valueMap = new Map(values.map((v) => [v.field_id, v]));
    const roleHasAllFields = (rid: string): boolean => {
      const roleFields = fields.filter((f) => f.assignedRoleId === rid);
      if (!roleFields.length) return true;
      return roleFields.every((f) => {
        const v = valueMap.get(f.id);
        if (!v) return false;
        const hasText =
          typeof v.value_text === 'string' && v.value_text.trim() !== '';
        const hasJson =
          v.value_json != null &&
          typeof v.value_json === 'object' &&
          Object.keys(v.value_json as Record<string, unknown>).length > 0;
        return hasText || hasJson;
      });
    };

    // Every role must be `submitted` AND have its fields filled to count.
    const allRolesDone =
      roles.length > 0 &&
      roles.every(
        (r) => r.status === 'submitted' && roleHasAllFields(r.role_id),
      );

    if (allRolesDone) {
      if (assignment.status !== 'completed') {
        assignment.status = 'completed';
        assignment.completed_at = new Date();
        await this.assignmentRepo.save(assignment);
      }
      return;
    }

    const anyProgress = roles.some(
      (r) => r.status === 'in_progress' || r.status === 'submitted',
    );
    const nextStatus = anyProgress ? 'in_progress' : 'sent';
    if (assignment.status !== nextStatus) {
      assignment.status = nextStatus;
      assignment.completed_at = null;
      await this.assignmentRepo.save(assignment);
    }
  }

  /**
   * Look up signer name + title for the SignedDocumentInfo audit block.
   * Mirrors the helper in `external-document.service.ts`. Best-effort —
   * never throws.
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
}
