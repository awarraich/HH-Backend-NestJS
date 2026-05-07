import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In } from 'typeorm';
import { CompetencyAssignment } from '../entities/competency-assignment.entity';
import { DocumentTemplateUserAssignment } from '../entities/document-template-user-assignment.entity';
import { CompetencyAssignmentRole } from '../entities/competency-assignment-role.entity';
import { CompetencyAssignmentFieldValue } from '../entities/competency-assignment-field-value.entity';
import { CreateAssignmentDto } from '../dto/create-assignment.dto';
import { FillAssignmentDto } from '../dto/fill-assignment.dto';
import { TemplatesService } from './templates.service';

@Injectable()
export class AssignmentsService {
  constructor(
    @InjectRepository(CompetencyAssignment)
    private readonly repo: Repository<CompetencyAssignment>,
    @InjectRepository(DocumentTemplateUserAssignment)
    private readonly templateUserRepo: Repository<DocumentTemplateUserAssignment>,
    @InjectRepository(CompetencyAssignmentRole)
    private readonly competencyRoleRepo: Repository<CompetencyAssignmentRole>,
    @InjectRepository(CompetencyAssignmentFieldValue)
    private readonly competencyValueRepo: Repository<CompetencyAssignmentFieldValue>,
    private readonly templatesService: TemplatesService,
  ) {}

  private mapAssignment(a: CompetencyAssignment) {
    if (!a) return a;
    const result = { ...a };
    if (result.template_snapshot?.pdf_file_key) {
      result.template_snapshot = {
        ...result.template_snapshot,
        pdfUrl: this.templatesService.buildPdfUrl(a.organization_id, result.template_snapshot.id)
      };
    }
    return result;
  }

  /**
   * Merge v2 per-instance field values into the legacy `field_values` JSONB
   * blob that the legacy filler UI reads from. v2 writes go to a separate
   * `competency_assignment_field_values` table; without this merge, HR
   * opening a v2 assignment in the legacy viewer sees blank fields even
   * after the employee filled them in. Legacy `field_values` always wins
   * if both exist (kept for back-compat with rows touched before v2 was
   * deployed).
   */
  private async mapAssignmentWithV2Values(a: CompetencyAssignment) {
    const result = this.mapAssignment(a);
    if (!result) return result;
    const v2Values = await this.competencyValueRepo.find({
      where: { assignment_id: a.id },
    });
    if (!v2Values.length) return result;
    const merged: Record<string, string> = { ...(result.field_values ?? {}) };
    for (const v of v2Values) {
      if (merged[v.field_id] != null) continue; // legacy wins on conflict
      if (v.value_text != null) {
        merged[v.field_id] = v.value_text;
      } else if (v.value_json != null) {
        merged[v.field_id] =
          typeof v.value_json === 'string'
            ? v.value_json
            : JSON.stringify(v.value_json);
      }
    }
    result.field_values = merged;
    return result;
  }

  /**
   * Look up which template roles a given user is mapped to, so the caller
   * (employee or supervisor) only sees fields they're actually authorised
   * to fill on the assignment they're opening. Powers the client-side
   * field-editability gate in the PDF filler.
   */
  private async getCallerRoleIds(
    templateId: string,
    userId: string,
  ): Promise<string[]> {
    const rows = await this.templateUserRepo.find({
      where: { template_id: templateId, user_id: userId },
    });
    return rows.map((r) => r.role_id);
  }

  /**
   * User-scoped mapping: merges v2 field values AND tags the record with
   * the caller's role IDs on this assignment's template. Used by every
   * endpoint where we know who's asking — the frontend only marks fields
   * as editable when their `assignedRoleId` is in this list, and v2 values
   * must be merged so employees see their previously-saved progress.
   */
  private async mapAssignmentForUser(
    a: CompetencyAssignment,
    userId: string,
  ) {
    const mapped = await this.mapAssignmentWithV2Values(a);
    if (!mapped) return mapped;
    const callerRoleIds = await this.getCallerRoleIds(a.template_id, userId);
    return { ...mapped, caller_role_ids: callerRoleIds };
  }

  async findAll(orgId: string, filters?: { status?: string; supervisorId?: string }) {
    const qb = this.repo
      .createQueryBuilder('a')
      .where('a.organization_id = :orgId', { orgId })
      .orderBy('a.created_at', 'DESC');

    if (filters?.status) {
      qb.andWhere('a.status = :status', { status: filters.status });
    }
    if (filters?.supervisorId) {
      qb.andWhere('a.supervisor_id = :sid', { sid: filters.supervisorId });
    }

    const assignments = await qb.getMany();
    return Promise.all(assignments.map((a) => this.mapAssignmentWithV2Values(a)));
  }

  async findOne(orgId: string, id: string, userId?: string) {
    const a = await this.repo.findOne({ where: { id, organization_id: orgId } });
    if (!a) throw new NotFoundException('Assignment not found');
    return userId
      ? this.mapAssignmentForUser(a, userId)
      : this.mapAssignmentWithV2Values(a);
  }

  async create(orgId: string, dto: CreateAssignmentDto, userId: string) {
    const template = await this.templatesService.findOne(orgId, dto.templateId);

    const snapshot = {
      id: template.id,
      name: template.name,
      description: template.description,
      roles: template.roles,
      document_fields: template.document_fields,
      pdf_file_key: template.pdf_file_key,
    };

    const saved = await this.repo.save(
      this.repo.create({
        organization_id: orgId,
        template_id: template.id,
        template_snapshot: snapshot,
        name: template.name || 'Untitled',
        supervisor_id: dto.supervisorId,
        status: 'sent',
        created_by: userId,
      }),
    );
    return this.mapAssignment(saved);
  }

  async fill(orgId: string, id: string, dto: FillAssignmentDto) {
    const a = await this.findOne(orgId, id);
    a.field_values = { ...a.field_values, ...dto.fieldValues };
    if (a.status === 'sent') a.status = 'in_progress';
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }

  /**
   * Server-side guard: drop any field the caller has no role to fill,
   * so a malicious or buggy client can't smuggle values into the
   * assignment by hand-crafting the request. Mirrors the editability
   * rule the UI uses to render the field grid. Empty `callerRoleIds`
   * means the user has no authority on this template — every field is
   * stripped.
   */
  private filterFieldValuesByCallerRoles(
    fieldValues: Record<string, string>,
    templateSnapshot: Record<string, any> | null,
    callerRoleIds: string[],
  ): Record<string, string> {
    if (!templateSnapshot) return {};
    const docFields: Array<{ id: string; assignedRoleId?: string | null }> =
      (templateSnapshot.document_fields as any[]) ?? [];
    const allowedIds = new Set(
      docFields
        .filter(
          (f) => f.assignedRoleId && callerRoleIds.includes(f.assignedRoleId),
        )
        .map((f) => f.id),
    );
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(fieldValues)) {
      if (allowedIds.has(k)) out[k] = v;
    }
    return out;
  }

  /**
   * User-scoped equivalent of `fill`. Authorises by checking that the
   * caller is either the supervisor on this assignment or has any
   * template-role assignment on the underlying template. Used by the
   * employee filler's autosave + final submit so employees can save
   * their own work without HR-level role permissions.
   */
  async fillForUser(id: string, userId: string, dto: FillAssignmentDto) {
    const a = await this.repo.findOne({ where: { id } });
    if (!a) throw new NotFoundException('Assignment not found');
    const callerRoleIds = await this.getCallerRoleIds(a.template_id, userId);
    const isSupervisor = a.supervisor_id === userId;
    if (!isSupervisor && callerRoleIds.length === 0) {
      throw new ForbiddenException(
        'You are not assigned to fill this document workflow.',
      );
    }
    if (a.status === 'completed' || a.status === 'voided') {
      throw new ForbiddenException(
        `Assignment is ${a.status} and can no longer be edited.`,
      );
    }
    // Strip values for fields the caller has no role to fill, so an
    // employee assigned only to the "Employee" role can't drop a value
    // into a "Manager" field by editing the request payload. The UI
    // already gates this — the backend enforces it.
    const allowedValues = this.filterFieldValuesByCallerRoles(
      dto.fieldValues,
      a.template_snapshot,
      callerRoleIds,
    );
    a.field_values = { ...a.field_values, ...allowedValues };
    if (a.status === 'sent') a.status = 'in_progress';
    const saved = await this.repo.save(a);
    return this.mapAssignmentForUser(saved, userId);
  }

  async submit(orgId: string, id: string) {
    const a = await this.findOne(orgId, id);
    a.status = 'completed';
    a.completed_at = new Date();
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }

  async void(orgId: string, id: string) {
    const a = await this.findOne(orgId, id);
    a.status = 'voided';
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }

  async delete(orgId: string, id: string) {
    const a = await this.findOne(orgId, id);
    await this.repo.remove(a);
  }

  async getForSupervisor(supervisorId: string) {
    const assignments = await this.repo.find({
      where: { supervisor_id: supervisorId, status: In(['sent', 'in_progress', 'completed']) },
      order: { created_at: 'DESC' },
    });
    return Promise.all(
      assignments.map((a) => this.mapAssignmentForUser(a, supervisorId)),
    );
  }

  /**
   * List competency assignments where the given user is involved in any
   * template role for this org. The link is indirect: an "employee" is
   * tied to templates via `document_template_user_assignments`, not
   * directly to a `competency_assignments` row. We therefore:
   *   1. find every template the user is assigned to,
   *   2. AND every template where they're the supervisor on an assignment,
   *   3. then fetch competency_assignments matching either path within the
   *      org, deduped by id.
   * This powers the "Document Workflows" panel on the employee HR File.
   */
  async getForEmployee(orgId: string | null | undefined, userId: string) {
    // Sources where the user could be linked to an assignment:
    //   1. Legacy `document_template_user_assignments` (template-scoped binding).
    //   2. Legacy `competency_assignments.supervisor_id` (single-supervisor row).
    //   3. v2 `competency_assignments.employee_user_id` (the target employee).
    //   4. v2 `competency_assignment_roles.user_id` (any role-filler — covers
    //      multi-supervisor v2 assignments where only one supervisor's id
    //      ends up in the legacy `supervisor_id` column).
    const [userTemplateRows, v2RoleRows] = await Promise.all([
      this.templateUserRepo
        .createQueryBuilder('ua')
        .select('DISTINCT ua.template_id', 'template_id')
        .where('ua.user_id = :userId', { userId })
        .getRawMany<{ template_id: string }>(),
      this.competencyRoleRepo
        .createQueryBuilder('cr')
        .select('DISTINCT cr.assignment_id', 'assignment_id')
        .where('cr.user_id = :userId', { userId })
        .getRawMany<{ assignment_id: string }>(),
    ]);
    const templateIds = userTemplateRows.map((r) => r.template_id);
    const v2AssignmentIds = v2RoleRows.map((r) => r.assignment_id);

    const qb = this.repo
      .createQueryBuilder('a')
      .orderBy('a.created_at', 'DESC');

    if (orgId) {
      qb.where('a.organization_id = :orgId', { orgId });
    }
    const clauses: string[] = [
      'a.supervisor_id = :userId',
      'a.employee_user_id = :userId',
    ];
    const params: Record<string, unknown> = { userId };
    if (templateIds.length > 0) {
      clauses.push('a.template_id IN (:...templateIds)');
      params.templateIds = templateIds;
    }
    if (v2AssignmentIds.length > 0) {
      clauses.push('a.id IN (:...v2AssignmentIds)');
      params.v2AssignmentIds = v2AssignmentIds;
    }
    qb.andWhere(`(${clauses.join(' OR ')})`, params);
    // Hide voided rows so a re-assignment of the same template doesn't keep
    // surfacing the prior (voided) instance alongside the fresh one.
    qb.andWhere('a.status != :voidedStatus', { voidedStatus: 'voided' });

    const assignments = await qb.getMany();
    return Promise.all(
      assignments.map((a) => this.mapAssignmentForUser(a, userId)),
    );
  }

  async employeeSign(id: string, signature: string) {
    const a = await this.repo.findOne({ where: { id } });
    if (!a) throw new NotFoundException('Assignment not found');
    a.employee_signature = signature;
    a.employee_signed_at = new Date();
    const saved = await this.repo.save(a);
    return this.mapAssignment(saved);
  }
}
