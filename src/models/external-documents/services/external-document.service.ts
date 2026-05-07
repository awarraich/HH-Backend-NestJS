import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { CompetencyTemplate } from '../../organizations/document-workflow/entities/competency-template.entity';
import { CompetencyTemplateVersion } from '../../organizations/document-workflow/entities/competency-template-version.entity';
import { DocumentTemplateUserAssignment } from '../../organizations/document-workflow/entities/document-template-user-assignment.entity';
import { DocumentAssignmentEvent } from '../../organizations/document-workflow/entities/document-assignment-event.entity';
import { User } from '../../../authentication/entities/user.entity';
import { Employee } from '../../employees/entities/employee.entity';
import { OrganizationStaff } from '../../organizations/staff-management/entities/organization-staff.entity';
import { DocumentFieldValue } from '../entities/document-field-value.entity';
import { SubmitExternalFieldsDto } from '../dto/submit-external-fields.dto';

@Injectable()
export class ExternalDocumentService {
  private readonly logger = new Logger(ExternalDocumentService.name);

  constructor(
    @InjectRepository(CompetencyTemplate)
    private readonly templateRepo: Repository<CompetencyTemplate>,
    @InjectRepository(CompetencyTemplateVersion)
    private readonly versionRepo: Repository<CompetencyTemplateVersion>,
    @InjectRepository(DocumentTemplateUserAssignment)
    private readonly userAssignmentRepo: Repository<DocumentTemplateUserAssignment>,
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(DocumentFieldValue)
    private readonly fieldValueRepo: Repository<DocumentFieldValue>,
    @InjectRepository(Employee)
    private readonly employeeRepo: Repository<Employee>,
    @InjectRepository(OrganizationStaff)
    private readonly orgStaffRepo: Repository<OrganizationStaff>,
    @InjectRepository(DocumentAssignmentEvent)
    private readonly eventRepo: Repository<DocumentAssignmentEvent>,
  ) {}

  /**
   * Resolve which template-fields snapshot a given assignment should
   * render against. Always prefer the pinned `template_version_id` so
   * the user sees the schema the assignment was created against —
   * never the live (mutable) template draft. Backfill makes this
   * column NOT NULL on every assignment, but we fall back to the
   * template's `current_version_id` (and finally the live template
   * itself) for safety in case a future code path forgets to pin.
   */
  private async resolveTemplateSnapshot(
    assignment: DocumentTemplateUserAssignment,
  ): Promise<{ document_fields: Record<string, unknown>[]; roles: Record<string, unknown>[]; pdf_file_key: string | null; organization_id: string | null }> {
    if (assignment.template_version_id) {
      const v = await this.versionRepo.findOne({
        where: { id: assignment.template_version_id },
      });
      if (v) {
        // Need org id for PDF URL — versions don't carry it; pull
        // from the parent template (a single FK lookup).
        const t = await this.templateRepo.findOne({
          where: { id: assignment.template_id },
          select: ['id', 'organization_id'],
        });
        return {
          document_fields: v.document_fields,
          roles: v.roles,
          pdf_file_key: v.pdf_file_key,
          organization_id: t?.organization_id ?? null,
        };
      }
    }
    // Fallback — should only fire for legacy rows mid-migration.
    const t = await this.templateRepo.findOne({ where: { id: assignment.template_id } });
    if (!t) throw new NotFoundException('Template not found');
    return {
      document_fields: t.document_fields,
      roles: t.roles,
      pdf_file_key: t.pdf_file_key,
      organization_id: t.organization_id,
    };
  }

  /** Append-only audit log writer. Captures who triggered which
   *  transition and persists the from/to status so a future support
   *  case can reconstruct the full history even if the assignment row
   *  has since moved through more states. Never throws — audit failure
   *  shouldn't break the user's action. */
  private async logAssignmentEvent(
    assignmentId: string,
    event: string,
    actorUserId: string | null,
    payload: Record<string, unknown> | null = null,
  ): Promise<void> {
    try {
      await this.eventRepo.save(
        this.eventRepo.create({
          assignment_id: assignmentId,
          event,
          actor_user_id: actorUserId,
          payload,
        }),
      );
    } catch (err) {
      this.logger.warn(
        `Failed to write assignment event ${event} for ${assignmentId}: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  /**
   * Look up the signer's display name and best-available job title for the
   * SignedDocumentInfo audit block. See the matching helper on
   * `OfferLetterAssignmentService.resolveSignerSnapshot` — kept duplicated
   * intentionally so each module owns its own dependencies and we don't
   * pull a job-management import into the legacy doc-workflow service.
   *
   * Title resolution: OrganizationStaff.position_title → staffRole.name →
   * Employee.position_title → null.
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

  private async validateUser(userId: string): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Get the set of field IDs assigned to a given role within a template's document_fields.
   */
  private getFieldIdsByRole(
    documentFields: Record<string, any>[],
    roleId: string,
  ): Set<string> {
    const ids = new Set<string>();
    for (const field of documentFields) {
      if (field.assignedRoleId === roleId) {
        ids.add(field.id);
      }
    }
    return ids;
  }

  /**
   * GET /v1/api/documents/my-assignments?userId=xxx
   *
   * Find all templates assigned to this user via document_template_user_assignments.
   * For each template, mark fields as editable based on the role the user was assigned.
   * Load ALL filled values from all users so everyone sees each other's data.
   */
  async getMyAssignments(userId: string) {
    await this.validateUser(userId);

    // Find all assignments for this user (with role info)
    const assignments = await this.userAssignmentRepo.find({
      where: { user_id: userId },
      relations: ['role'],
    });

    if (!assignments.length) {
      return [];
    }

    // Group assignments by (template_id, version_id) so users seeing
    // different versions of the same template (e.g. one assignment
    // pinned to v1 + another to v2 after a republish) get distinct
    // entries with their own field schemas. Falls back to a synthetic
    // 'live' bucket for any legacy rows missing a version pin.
    type Bucket = {
      template_id: string;
      version_id: string | null;
      role_ids: string[];
    };
    const buckets = new Map<string, Bucket>();
    for (const a of assignments) {
      const key = `${a.template_id}:${a.template_version_id ?? 'live'}`;
      const b = buckets.get(key) ?? {
        template_id: a.template_id,
        version_id: a.template_version_id ?? null,
        role_ids: [],
      };
      b.role_ids.push(a.role_id);
      buckets.set(key, b);
    }

    const templateIds = [...new Set([...buckets.values()].map((b) => b.template_id))];
    const versionIds = [...new Set([...buckets.values()].map((b) => b.version_id).filter((v): v is string => !!v))];

    // Load template parents (for org_id + name + description) plus the
    // pinned version snapshots in two parallel queries — neither blocks
    // the other.
    const [templates, versions, allValues] = await Promise.all([
      this.templateRepo.createQueryBuilder('t').whereInIds(templateIds).orderBy('t.updated_at', 'DESC').getMany(),
      versionIds.length > 0
        ? this.versionRepo.createQueryBuilder('v').whereInIds(versionIds).getMany()
        : Promise.resolve([] as CompetencyTemplateVersion[]),
      // Values are keyed by (template_version_id, field_id, user_id)
      // post-Phase-3, so we scope by version when possible. Legacy
      // rows still match via template_id; the OR keeps both paths
      // working during the rollout window.
      this.fieldValueRepo
        .createQueryBuilder('fv')
        .where('fv.template_id IN (:...templateIds)', { templateIds })
        .getMany(),
    ]);

    const templateById = new Map(templates.map((t) => [t.id, t]));
    const versionById = new Map(versions.map((v) => [v.id, v]));

    // Index values by (version_id, field_id) primarily, with a
    // (template_id, field_id) fallback for legacy rows where
    // template_version_id was never populated.
    type Filled = { value: unknown; user_id: string; signature_audit: Record<string, unknown> | null };
    const valueByVersion = new Map<string, Filled>();
    const valueByTemplate = new Map<string, Filled>();
    for (const fv of allValues) {
      const filled: Filled = {
        value: fv.value,
        user_id: fv.user_id,
        signature_audit: fv.signature_audit ?? null,
      };
      if (fv.template_version_id) {
        valueByVersion.set(`${fv.template_version_id}:${fv.field_id}`, filled);
      }
      valueByTemplate.set(`${fv.template_id}:${fv.field_id}`, filled);
    }

    return [...buckets.values()].map((bucket) => {
      const template = templateById.get(bucket.template_id);
      const version = bucket.version_id ? versionById.get(bucket.version_id) : null;

      // Snapshot wins; live template only fills the gap for legacy
      // assignments missing a version pin.
      const documentFields = (version?.document_fields ?? template?.document_fields ?? []) as Record<string, any>[];
      const roles = (version?.roles ?? template?.roles ?? []) as Record<string, unknown>[];
      const pdfFileKey = version?.pdf_file_key ?? template?.pdf_file_key ?? null;

      const editableFieldIds = new Set<string>();
      for (const roleId of bucket.role_ids) {
        const ids = this.getFieldIdsByRole(documentFields, roleId);
        ids.forEach((id) => editableFieldIds.add(id));
      }

      const fields = documentFields.map((field) => {
        const isEditable = editableFieldIds.has(field.id);
        const saved =
          (bucket.version_id && valueByVersion.get(`${bucket.version_id}:${field.id}`)) ||
          valueByTemplate.get(`${bucket.template_id}:${field.id}`);
        return {
          ...field,
          isEditable,
          ...(saved
            ? {
                filledValue: saved.value,
                filledBy: saved.user_id,
                signatureAudit: saved.signature_audit,
              }
            : {}),
        };
      });

      return {
        template_id: bucket.template_id,
        template_version_id: bucket.version_id,
        version_number: version?.version_number ?? null,
        name: template?.name ?? '',
        description: template?.description ?? '',
        assignedRoles: bucket.role_ids,
        roles,
        pdfUrl: pdfFileKey && template
          ? `/v1/api/organizations/${template.organization_id}/document-workflow/templates/${template.id}/pdf/view`
          : null,
        fields,
      };
    });
  }

  /**
   * POST /v1/api/documents/:templateId/submit
   *
   * Submit field values for a user.
   * Validates user is assigned to this template with the given role.
   * Only fields with assignedRoleId matching the given roleId are accepted.
   */
  async submitFields(templateId: string, dto: SubmitExternalFieldsDto) {
    await this.validateUser(dto.userId);

    // Verify user is assigned to this template with this role
    const assignment = await this.userAssignmentRepo.findOne({
      where: {
        template_id: templateId,
        user_id: dto.userId,
        role_id: dto.roleId,
      },
    });
    if (!assignment) {
      throw new ForbiddenException('You are not assigned to this template with this role');
    }

    const template = await this.templateRepo.findOne({ where: { id: templateId } });
    if (!template) {
      throw new NotFoundException('Template not found');
    }

    // Resolve the snapshot the assignment is pinned to — that's the
    // schema source-of-truth for what fields exist and which role is
    // allowed to fill them. The live template draft may have moved on;
    // saving against it would let an admin re-publish and silently shift
    // what fields the user is "authorized" to fill mid-flow.
    const snapshot = await this.resolveTemplateSnapshot(assignment);
    const documentFields = snapshot.document_fields as Record<string, unknown>[];

    const assignedFieldIds = this.getFieldIdsByRole(
      documentFields as Record<string, any>[],
      dto.roleId,
    );

    if (assignedFieldIds.size === 0) {
      throw new ForbiddenException('No fields are assigned to this role on this template');
    }

    const rejectedFields: string[] = [];
    for (const item of dto.fields) {
      if (!assignedFieldIds.has(item.fieldId)) {
        rejectedFields.push(item.fieldId);
      }
    }
    if (rejectedFields.length > 0) {
      throw new BadRequestException(
        `You are not authorized to fill these fields: ${rejectedFields.join(', ')}`,
      );
    }

    // Pre-compute which of the submitted fields are signature/initials so
    // we only do the (relatively expensive) signer-snapshot lookup once
    // per request — not once per field — and only when at least one
    // signature is being saved.
    const isSignatureField = (fieldId: string): boolean => {
      const f = documentFields.find(
        (x) => (x as { id?: string }).id === fieldId,
      ) as Record<string, unknown> | undefined;
      if (!f) return false;
      const t = String(f.type ?? '').toLowerCase();
      if (t === 'signature' || t === 'initials') return true;
      const label = String(f.label ?? '').toLowerCase();
      return label.startsWith('signature') || label.startsWith('initials');
    };
    const touchesSignatureField = dto.fields.some((f) =>
      isSignatureField(f.fieldId),
    );
    const signerSnapshot = touchesSignatureField
      ? await this.resolveSignerSnapshot(
          dto.userId,
          snapshot.organization_id,
        )
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
      if (!isSignatureField(fieldId)) return null;
      return {
        signedAt: new Date().toISOString(),
        signerName: signerSnapshot.name,
        signerTitle: signerSnapshot.title,
        geolocation: geolocationSnapshot,
      };
    };

    const saved: DocumentFieldValue[] = [];
    for (const item of dto.fields) {
      // Lookup is now scoped to (version, field, user) — the new unique
      // constraint. Without the version_id filter, two assignments on
      // different versions of the same template would silently overwrite
      // each other's saved values.
      const existing = await this.fieldValueRepo.findOne({
        where: {
          template_version_id: assignment.template_version_id,
          field_id: item.fieldId,
          user_id: dto.userId,
        },
      });
      const audit = buildSignatureAudit(item.fieldId);

      if (existing) {
        existing.value = item.value;
        if (audit) existing.signature_audit = audit;
        saved.push(await this.fieldValueRepo.save(existing));
      } else {
        saved.push(
          await this.fieldValueRepo.save(
            this.fieldValueRepo.create({
              template_id: templateId,
              template_version_id: assignment.template_version_id,
              field_id: item.fieldId,
              user_id: dto.userId,
              value: item.value,
              signature_audit: audit,
            }),
          ),
        );
      }
    }

    // Recompute the assignment lifecycle status now that we've persisted
    // new field values. Pass the resolved snapshot so the count uses the
    // version's `document_fields` — not the live template, which may
    // have a different field set.
    await this.recomputeAssignmentStatus(
      assignment,
      documentFields as Record<string, any>[],
      dto.roleId,
    );

    return saved.map((fv) => ({
      id: fv.id,
      template_id: fv.template_id,
      field_id: fv.field_id,
      user_id: fv.user_id,
      value: fv.value,
      signature_audit: fv.signature_audit,
      created_at: fv.created_at,
      updated_at: fv.updated_at,
    }));
  }

  /**
   * Recompute and persist the lifecycle status of a template assignment
   * based on the saved field values. Intentionally narrow — looks at the
   * fields THIS role is responsible for (not all fields on the template),
   * since multi-role workflows route different fields to different roles
   * and a clinician is "done" when their own fields are filled.
   *
   *   pending     — no values saved by this user for this template yet
   *   in_progress — some role-required fields saved, not all
   *   completed   — every role-required field has a saved value
   *
   * `started_at` is stamped on the first save and never overwritten; if a
   * value is later edited the timestamp still reflects when work began.
   * `completed_at` is set when reaching 'completed' and cleared if a
   * future save (after a field schema change) drops back to in_progress.
   *
   * Saves a single UPDATE — cheap to call after every submitFields().
   */
  private async recomputeAssignmentStatus(
    assignment: DocumentTemplateUserAssignment,
    documentFields: Record<string, any>[],
    roleId: string,
  ): Promise<void> {
    const requiredFieldIds = this.getFieldIdsByRole(documentFields, roleId);

    let nextStatus: string;
    let nextCompletedAt: Date | null;
    if (requiredFieldIds.size === 0) {
      // Degenerate: no fields routed to this role. Nothing to track —
      // leave the assignment at its current state rather than guessing.
      return;
    } else {
      // Scope the count to this assignment's pinned version so a fresh
      // assignment on v2 doesn't see v1's old saved values and
      // misreport itself as already in_progress / completed.
      const filledCount = await this.fieldValueRepo.count({
        where: {
          template_version_id: assignment.template_version_id,
          user_id: assignment.user_id,
          field_id: In([...requiredFieldIds]),
        },
      });
      if (filledCount === 0) {
        nextStatus = 'pending';
        nextCompletedAt = null;
      } else if (filledCount >= requiredFieldIds.size) {
        nextStatus = 'completed';
        nextCompletedAt = new Date();
      } else {
        nextStatus = 'in_progress';
        nextCompletedAt = null;
      }
    }

    // Don't trample reviewer state. Once an assignment has been
    // submitted/approved/rejected, leaving it alone here means
    // re-saving a field value won't silently downgrade an approved
    // form back to in_progress. Re-fill after rejection goes through
    // /reopen explicitly, which is the audit-friendly path.
    const REVIEWER_STATES = new Set(['submitted', 'approved', 'rejected']);
    if (REVIEWER_STATES.has(assignment.status)) return;

    const update: Partial<DocumentTemplateUserAssignment> = {
      status: nextStatus,
      completed_at: nextCompletedAt,
    };
    // Stamp started_at exactly once — on the pending → in_progress (or
    // pending → completed in one shot) transition.
    if (!assignment.started_at && nextStatus !== 'pending') {
      update.started_at = new Date();
    }
    await this.userAssignmentRepo.update(assignment.id, update);

    // System-driven events — actor is null since the user just saved a
    // field; the status flip is a derived consequence, not an action
    // they took directly.
    if (assignment.status !== nextStatus) {
      if (assignment.status === 'pending' && nextStatus !== 'pending') {
        await this.logAssignmentEvent(assignment.id, 'started', null, {
          from_status: assignment.status,
          to_status: nextStatus,
        });
      }
      if (nextStatus === 'completed') {
        await this.logAssignmentEvent(assignment.id, 'completed', null, {
          from_status: assignment.status,
          to_status: nextStatus,
        });
      }
    }
  }

  // ─── Phase 2: Submission / approval lifecycle ─────────────────────
  //
  // Four explicit transitions on top of the auto-`completed` state from
  // Phase 1. Each method validates the caller's authority, enforces a
  // legal `from` state, writes the new state in one UPDATE, and logs an
  // append-only event.

  /**
   * Employee marks a completed assignment as ready for HR review.
   * Only valid when the template requires review and the assignment is
   * in `completed`. Submitting on behalf of someone else (HR doing it
   * for an absent employee) is allowed but the actor is recorded for
   * audit.
   */
  async submitAssignment(assignmentId: string, actorUserId: string): Promise<DocumentTemplateUserAssignment> {
    const assignment = await this.userAssignmentRepo.findOne({ where: { id: assignmentId } });
    if (!assignment) throw new NotFoundException('Assignment not found');
    const template = await this.templateRepo.findOne({ where: { id: assignment.template_id } });
    if (!template) throw new NotFoundException('Template not found');

    if (!template.requires_review) {
      throw new BadRequestException('This template does not require review — completed is terminal.');
    }
    if (assignment.status !== 'completed') {
      throw new BadRequestException(
        `Can only submit a completed assignment (current status: ${assignment.status}).`,
      );
    }

    const fromStatus = assignment.status;
    await this.userAssignmentRepo.update(assignmentId, {
      status: 'submitted',
      submitted_at: new Date(),
      submitted_by: actorUserId,
      // Clear stale rejection from a previous round so it doesn't
      // confuse the reviewer when this resubmission lands.
      rejection_reason: null,
    });
    await this.logAssignmentEvent(assignmentId, 'submitted', actorUserId, {
      from_status: fromStatus,
      to_status: 'submitted',
    });
    return (await this.userAssignmentRepo.findOne({ where: { id: assignmentId } }))!;
  }

  /**
   * Admin approves a submitted assignment. Marks reviewed_at /
   * reviewed_by so HR audits know who signed off and when. Only valid
   * from `submitted`.
   */
  async approveAssignment(assignmentId: string, actorUserId: string): Promise<DocumentTemplateUserAssignment> {
    const assignment = await this.userAssignmentRepo.findOne({ where: { id: assignmentId } });
    if (!assignment) throw new NotFoundException('Assignment not found');
    if (assignment.status !== 'submitted') {
      throw new BadRequestException(
        `Can only approve a submitted assignment (current status: ${assignment.status}).`,
      );
    }

    await this.userAssignmentRepo.update(assignmentId, {
      status: 'approved',
      reviewed_at: new Date(),
      reviewed_by: actorUserId,
      rejection_reason: null,
    });
    await this.logAssignmentEvent(assignmentId, 'approved', actorUserId, {
      from_status: 'submitted',
      to_status: 'approved',
    });
    return (await this.userAssignmentRepo.findOne({ where: { id: assignmentId } }))!;
  }

  /**
   * Admin rejects a submitted assignment with a reason the employee
   * sees on their HR File. Status returns to `rejected` (not directly
   * to in_progress) so the rejection itself is a discoverable state —
   * the employee's portal can render "Rejected · here's why" rather
   * than silently bumping it back to "needs action."
   */
  async rejectAssignment(
    assignmentId: string,
    actorUserId: string,
    reason: string,
  ): Promise<DocumentTemplateUserAssignment> {
    if (!reason || !reason.trim()) {
      throw new BadRequestException('A rejection reason is required so the employee knows what to fix.');
    }
    const assignment = await this.userAssignmentRepo.findOne({ where: { id: assignmentId } });
    if (!assignment) throw new NotFoundException('Assignment not found');
    if (assignment.status !== 'submitted') {
      throw new BadRequestException(
        `Can only reject a submitted assignment (current status: ${assignment.status}).`,
      );
    }

    await this.userAssignmentRepo.update(assignmentId, {
      status: 'rejected',
      reviewed_at: new Date(),
      reviewed_by: actorUserId,
      rejection_reason: reason.trim(),
    });
    await this.logAssignmentEvent(assignmentId, 'rejected', actorUserId, {
      from_status: 'submitted',
      to_status: 'rejected',
      reason: reason.trim(),
    });
    return (await this.userAssignmentRepo.findOne({ where: { id: assignmentId } }))!;
  }

  /**
   * Admin reopens an approved/rejected/completed assignment so the
   * employee can edit again. Resets back to `in_progress` (or
   * `pending` if no values exist) and clears reviewer state. The audit
   * log preserves the previous lifecycle so this isn't lossy.
   */
  async reopenAssignment(assignmentId: string, actorUserId: string): Promise<DocumentTemplateUserAssignment> {
    const assignment = await this.userAssignmentRepo.findOne({ where: { id: assignmentId } });
    if (!assignment) throw new NotFoundException('Assignment not found');
    const REOPENABLE = new Set(['completed', 'submitted', 'approved', 'rejected']);
    if (!REOPENABLE.has(assignment.status)) {
      throw new BadRequestException(
        `Nothing to reopen — assignment is already in ${assignment.status}.`,
      );
    }

    // Decide the post-reopen status from the underlying values rather
    // than blindly going to in_progress: an admin reopening a
    // submitted+then-approved-by-mistake assignment shouldn't have to
    // wonder whether the user's prior data is still there. Read the
    // pinned snapshot, not the live template, so a republish between
    // submission and reopen doesn't change the field set we count
    // against.
    const snapshot = await this.resolveTemplateSnapshot(assignment);
    let nextStatus = 'pending';
    const requiredFieldIds = this.getFieldIdsByRole(
      snapshot.document_fields as Record<string, any>[],
      assignment.role_id,
    );
    if (requiredFieldIds.size > 0) {
      const filled = await this.fieldValueRepo.count({
        where: {
          template_version_id: assignment.template_version_id,
          user_id: assignment.user_id,
          field_id: In([...requiredFieldIds]),
        },
      });
      if (filled === 0) nextStatus = 'pending';
      else if (filled >= requiredFieldIds.size) nextStatus = 'in_progress'; // intentional: even fully-filled rows reopen to in_progress so the auto-complete event re-fires on next save
      else nextStatus = 'in_progress';
    }

    const fromStatus = assignment.status;
    await this.userAssignmentRepo.update(assignmentId, {
      status: nextStatus,
      submitted_at: null,
      submitted_by: null,
      reviewed_at: null,
      reviewed_by: null,
      rejection_reason: null,
      completed_at: null,
    });
    await this.logAssignmentEvent(assignmentId, 'reopened', actorUserId, {
      from_status: fromStatus,
      to_status: nextStatus,
    });
    return (await this.userAssignmentRepo.findOne({ where: { id: assignmentId } }))!;
  }
}
