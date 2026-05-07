import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';

type DependentRow = {
  status: string;
  firstName: string | null;
  lastName: string | null;
  email: string | null;
};
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { CompetencyTemplate } from '../entities/competency-template.entity';
import { CompetencyTemplateVersion } from '../entities/competency-template-version.entity';
import { DocumentFieldValue } from '../../../external-documents/entities/document-field-value.entity';
import { DocumentWorkflowRole } from '../entities/document-workflow-role.entity';
import { CreateTemplateDto } from '../dto/create-template.dto';
import { UpdateTemplateDto } from '../dto/update-template.dto';
import { PdfStorageService } from './pdf-storage.service';
import { S3Service } from '../../../../common/services/s3/s3.service';

@Injectable()
export class TemplatesService {
  constructor(
    @InjectRepository(CompetencyTemplate)
    private readonly repo: Repository<CompetencyTemplate>,
    @InjectRepository(CompetencyTemplateVersion)
    private readonly versionRepo: Repository<CompetencyTemplateVersion>,
    @InjectRepository(DocumentFieldValue)
    private readonly fieldValueRepo: Repository<DocumentFieldValue>,
    @InjectRepository(DocumentWorkflowRole)
    private readonly roleRepo: Repository<DocumentWorkflowRole>,
    private readonly pdfStorage: PdfStorageService,
    private readonly s3Service: S3Service,
  ) {}

  /**
   * Snapshot the current draft state of a template into a new
   * `competency_template_versions` row and bump the template's
   * `current_version_id` to point at it. Idempotent in a useful sense:
   * calling publish twice produces two distinct version rows so the
   * audit trail captures both publish events. New assignments freeze on
   * `current_version_id` at assign time, so old assignments are
   * unaffected.
   *
   * `version_number` is computed as `MAX(existing) + 1` per template.
   * The unique constraint (template_id, version_number) catches racing
   * publishes; we let the second one fail rather than building a real
   * advisory lock — publish is a low-frequency admin action.
   */
  async publishVersion(
    orgId: string,
    templateId: string,
    publishedBy: string | null,
  ): Promise<CompetencyTemplateVersion> {
    const template = await this.findOne(orgId, templateId);

    const latest = await this.versionRepo
      .createQueryBuilder('v')
      .where('v.template_id = :tid', { tid: templateId })
      .orderBy('v.version_number', 'DESC')
      .getOne();
    const nextVersion = (latest?.version_number ?? 0) + 1;

    const snapshot = await this.versionRepo.save(
      this.versionRepo.create({
        template_id: template.id,
        version_number: nextVersion,
        document_fields: template.document_fields ?? [],
        roles: template.roles ?? [],
        pdf_file_key: template.pdf_file_key,
        pdf_original_name: template.pdf_original_name,
        pdf_size_bytes: template.pdf_size_bytes,
        published_by: publishedBy,
      }),
    );

    await this.repo.update(template.id, { current_version_id: snapshot.id });
    return snapshot;
  }

  async findAll(orgId: string, purpose?: 'document' | 'applicant_form') {
    const where: Record<string, unknown> = { organization_id: orgId };
    if (purpose) {
      where.purpose = purpose;
    }
    const templates = await this.repo.find({ where, order: { updated_at: 'DESC' } });
    return templates.map((t) => {
      if (t.pdf_file_key) {
        return { ...t, pdfUrl: this.buildPdfUrl(t.organization_id, t.id) };
      }
      return t;
    });
  }

  async findOne(orgId: string, id: string) {
    const t = await this.repo.findOne({ where: { id, organization_id: orgId } });
    if (!t) throw new NotFoundException('Template not found');
    if (t.pdf_file_key) {
      (t as any).pdfUrl = this.buildPdfUrl(orgId, id);
    }
    return t;
  }

  async getPdfSignedUrl(orgId: string, id: string): Promise<{ url: string; fileName: string }> {
    const t = await this.repo.findOne({ where: { id, organization_id: orgId } });
    if (!t || !t.pdf_file_key) throw new NotFoundException('PDF not found');
    const url = await this.pdfStorage.getPresignedUrl(t.pdf_file_key);
    return { url, fileName: t.pdf_original_name ?? 'document.pdf' };
  }

  /**
   * Fetch the template PDF bytes from S3 — for server-side processing like
   * pdf-lib overlays or signed-field rendering. Callers that need streaming
   * to an HTTP response should prefer `getPdfSignedUrl` and redirect instead.
   */
  async getPdfBuffer(
    orgId: string,
    id: string,
  ): Promise<{ buffer: Buffer; contentType: string; fileName: string }> {
    const t = await this.repo.findOne({ where: { id, organization_id: orgId } });
    if (!t || !t.pdf_file_key) throw new NotFoundException('PDF not found');
    const buffer = await this.s3Service.getObjectAsBuffer(t.pdf_file_key);
    return {
      buffer,
      contentType: 'application/pdf',
      fileName: t.pdf_original_name ?? 'document.pdf',
    };
  }

  buildPdfUrl(orgId: string, templateId: string): string {
    return `/v1/api/organizations/${orgId}/document-workflow/templates/${templateId}/pdf/view`;
  }

  private buildFieldsWithValues(
    documentFields: any[],
    valueMap: Map<string, { value: any; user_id: string }>,
    roleNameMap: Map<string, string>,
  ): any[] {
    return (documentFields ?? []).map((field: any) => {
      const saved = valueMap.get(field.id);
      return {
        ...field,
        assignedRoleName: field.assignedRoleId
          ? roleNameMap.get(field.assignedRoleId) ?? null
          : null,
        filledValue: saved?.value ?? null,
        filledBy: saved?.user_id ?? null,
      };
    });
  }

  private async loadFieldValueMap(
    templateIds: string[],
  ): Promise<Map<string, Map<string, { value: any; user_id: string }>>> {
    if (!templateIds.length) return new Map();
    const fieldValues = await this.fieldValueRepo.find({
      where: { template_id: In(templateIds) },
    });
    const byTemplate = new Map<string, Map<string, { value: any; user_id: string }>>();
    for (const fv of fieldValues) {
      if (!byTemplate.has(fv.template_id)) byTemplate.set(fv.template_id, new Map());
      byTemplate.get(fv.template_id)!.set(fv.field_id, {
        value: fv.value,
        user_id: fv.user_id,
      });
    }
    return byTemplate;
  }

  private async loadRoleNameMap(templates: CompetencyTemplate[]): Promise<Map<string, string>> {
    const roleIds = new Set<string>();
    for (const t of templates) {
      for (const field of t.document_fields ?? []) {
        if (field.assignedRoleId) roleIds.add(field.assignedRoleId);
      }
    }
    if (roleIds.size === 0) return new Map();
    const roles = await this.roleRepo.find({ where: { id: In([...roleIds]) } });
    return new Map(roles.map((r) => [r.id, r.name]));
  }

  async findFilledTemplates(
    orgId: string,
    page: number = 1,
    limit: number = 20,
  ): Promise<{ data: any[]; total: number; page: number; limit: number }> {
    const [templates, total] = await this.repo.findAndCount({
      where: { organization_id: orgId },
      order: { updated_at: 'DESC' },
      skip: (page - 1) * limit,
      take: limit,
    });

    if (!templates.length) return { data: [], total: 0, page, limit };

    const templateIds = templates.map((t) => t.id);
    const [byTemplate, roleNameMap] = await Promise.all([
      this.loadFieldValueMap(templateIds),
      this.loadRoleNameMap(templates),
    ]);

    const data = templates.map((t) => {
      const valueMap = byTemplate.get(t.id) ?? new Map();
      return {
        id: t.id,
        organization_id: t.organization_id,
        name: t.name,
        description: t.description,
        roles: t.roles,
        document_fields: this.buildFieldsWithValues(t.document_fields, valueMap, roleNameMap),
        pdf_file_key: t.pdf_file_key ?? null,
        pdfUrl: t.pdf_file_key ? this.buildPdfUrl(t.organization_id, t.id) : null,
        created_by: t.created_by,
        created_at: t.created_at,
        updated_at: t.updated_at,
      };
    });

    return { data, total, page, limit };
  }

  async findByIdsWithValues(templateIds: string[]): Promise<any[]> {
    if (!templateIds.length) return [];
    const templates = await this.repo.find({ where: { id: In(templateIds) } });
    const [byTemplate, roleNameMap] = await Promise.all([
      this.loadFieldValueMap(templateIds),
      this.loadRoleNameMap(templates),
    ]);

    return templates.map((t) => {
      const valueMap = byTemplate.get(t.id) ?? new Map();
      return {
        id: t.id,
        organization_id: t.organization_id,
        name: t.name,
        description: t.description,
        roles: t.roles,
        document_fields: this.buildFieldsWithValues(t.document_fields, valueMap, roleNameMap),
        pdf_file_key: t.pdf_file_key ?? null,
        pdfUrl: t.pdf_file_key ? this.buildPdfUrl(t.organization_id, t.id) : null,
        created_by: t.created_by,
        created_at: t.created_at,
        updated_at: t.updated_at,
      };
    });
  }

  async create(orgId: string, dto: CreateTemplateDto, userId: string) {
    const saved = await this.repo.save(
      this.repo.create({
        organization_id: orgId,
        name: dto.name,
        description: dto.description ?? '',
        document_fields: dto.documentFields ?? [],
        roles: dto.roles ?? [],
        created_by: userId,
        purpose: dto.purpose === 'applicant_form' ? 'applicant_form' : 'document',
      }),
    );
    // Auto-publish v1 on create so the template is immediately
    // assignable. Without this, every new template would need a
    // separate Publish click before the assign modal could pin a
    // version_id to it. The v1 snapshot captures the initial state.
    await this.publishVersion(orgId, saved.id, userId);
    // Re-fetch so callers see the populated `current_version_id`
    // pointer alongside the rest of the template payload.
    return this.repo.findOne({ where: { id: saved.id } });
  }

  async update(orgId: string, id: string, dto: UpdateTemplateDto) {
    const t = await this.findOne(orgId, id);
    if (dto.name !== undefined) t.name = dto.name;
    if (dto.description !== undefined) t.description = dto.description;
    if (dto.documentFields !== undefined) t.document_fields = dto.documentFields;
    if (dto.roles !== undefined) t.roles = dto.roles;
    return this.repo.save(t);
  }

  async presignPdfUpload(orgId: string, id: string, filename: string, contentType: string) {
    await this.findOne(orgId, id);
    return this.pdfStorage.presignUpload(orgId, id, filename, contentType);
  }

  async confirmPdfUpload(
    orgId: string,
    id: string,
    payload: { key: string; fileName: string; sizeBytes?: number },
  ) {
    const t = await this.findOne(orgId, id);
    const previousKey = t.pdf_file_key;
    t.pdf_file_key = payload.key;
    t.pdf_original_name = payload.fileName;
    t.pdf_size_bytes = payload.sizeBytes ?? null;
    const saved = await this.repo.save(t);
    if (previousKey && previousKey !== payload.key) {
      // Offer-letter and competency assignments freeze a `template_snapshot`
      // that includes `pdf_file_key` at send time. If we nuke the old S3
      // object after a "Replace PDF", any applicant viewing their
      // already-sent offer letter would 404 on the PDF because their
      // snapshot still points at the deleted key. Check both snapshot
      // tables and only garbage-collect the file when nothing references
      // it anymore — even voided/completed rows hold a claim because HR
      // may still need to audit the signed document.
      const stillReferenced = await this.isPdfKeyReferencedBySnapshot(previousKey);
      if (!stillReferenced) {
        this.pdfStorage.delete(previousKey).catch(() => {});
      }
    }
    return saved;
  }

  /**
   * Does any frozen assignment snapshot still point at this S3 key? Queries
   * the two jsonb snapshot tables via raw SQL so we don't need to pull the
   * job-management entities into this module's DI graph.
   */
  private async isPdfKeyReferencedBySnapshot(key: string): Promise<boolean> {
    const offerRows = await this.repo.manager.query(
      `SELECT 1 FROM offer_letter_assignments
         WHERE template_snapshot->>'pdf_file_key' = $1 LIMIT 1`,
      [key],
    );
    if (offerRows.length > 0) return true;
    const competencyRows = await this.repo.manager.query(
      `SELECT 1 FROM competency_assignments
         WHERE template_snapshot->>'pdf_file_key' = $1 LIMIT 1`,
      [key],
    );
    return competencyRows.length > 0;
  }

  async delete(orgId: string, id: string) {
    const t = await this.findOne(orgId, id);
    const pdfKey = t.pdf_file_key;

    // Pre-check for RESTRICT-blocked parents so HR sees exactly which
    // recipients are holding the template in place ("Can't delete — sent
    // to Jane Doe, John Smith, and 2 more") rather than a generic FK
    // error. The catch below stays as a safety net in case a concurrent
    // send races past the pre-check.
    const dependents = await this.findTemplateDependents(id);
    if (
      dependents.offerRows.length > 0 ||
      dependents.competencyRows.length > 0
    ) {
      throw new ConflictException(this.formatDependentMessage(dependents));
    }

    // Clean up template-scoped per-user field fills before the template row
    // itself. Job-application submissions and in-progress fills live in
    // document_field_values without a CASCADE constraint, so leaving them
    // would either orphan junk or trigger a FK violation depending on the
    // DB-level constraint. Voiding these here is safe — the owning template
    // is about to be gone.
    await this.fieldValueRepo.delete({ template_id: id });

    try {
      await this.repo.remove(t);
    } catch (err) {
      // 23503 = foreign_key_violation. Shouldn't fire after the pre-check
      // but keep a readable fallback in case a race slips one through.
      const code =
        (err as { driverError?: { code?: string } })?.driverError?.code ??
        (err as { code?: string })?.code;
      if (code === '23503') {
        const fresh = await this.findTemplateDependents(id);
        throw new ConflictException(this.formatDependentMessage(fresh));
      }
      throw err;
    }

    if (pdfKey) {
      // Best-effort: the DB is now consistent, don't surface a storage
      // failure to the caller just to avoid leaving a PDF blob in S3.
      this.pdfStorage.delete(pdfKey).catch(() => {});
    }
  }

  /**
   * Collect the rows in `offer_letter_assignments` and
   * `competency_assignments` that point at this template, joined to the
   * user they were sent to (applicant for offers, supervisor for
   * assignments). Used to produce a specific delete-blocked message.
   */
  private async findTemplateDependents(templateId: string): Promise<{
    offerRows: DependentRow[];
    competencyRows: DependentRow[];
  }> {
    const offerRows: DependentRow[] = await this.repo.manager.query(
      `SELECT ola.status AS status,
              u."firstName" AS "firstName",
              u."lastName"  AS "lastName",
              u.email       AS email
         FROM offer_letter_assignments ola
         LEFT JOIN job_applications ja ON ja.id = ola.job_application_id
         LEFT JOIN users u ON u.id = ja.applicant_user_id
         WHERE ola.template_id = $1
         ORDER BY ola.created_at DESC`,
      [templateId],
    );
    const competencyRows: DependentRow[] = await this.repo.manager.query(
      `SELECT ca.status AS status,
              u."firstName" AS "firstName",
              u."lastName"  AS "lastName",
              u.email       AS email
         FROM competency_assignments ca
         LEFT JOIN users u ON u.id = ca.supervisor_id
         WHERE ca.template_id = $1
         ORDER BY ca.created_at DESC`,
      [templateId],
    );
    return { offerRows, competencyRows };
  }

  private formatDependentMessage(dependents: {
    offerRows: DependentRow[];
    competencyRows: DependentRow[];
  }): string {
    const displayName = (row: DependentRow): string => {
      const name = [row.firstName, row.lastName]
        .filter(Boolean)
        .join(' ')
        .trim();
      return name || row.email || 'an unnamed recipient';
    };

    const describe = (rows: DependentRow[], noun: string): string => {
      const n = rows.length;
      const preview = rows.slice(0, 3).map(displayName);
      const extra = n - preview.length;
      const tail = extra > 0 ? ` and ${extra} more` : '';
      const label = n === 1 ? noun : `${noun}s`;
      return `${n} ${label} sent to ${preview.join(', ')}${tail}`;
    };

    const parts: string[] = [];
    if (dependents.offerRows.length > 0) {
      parts.push(describe(dependents.offerRows, 'offer letter'));
    }
    if (dependents.competencyRows.length > 0) {
      parts.push(describe(dependents.competencyRows, 'assignment'));
    }
    const joined = parts.join(' and ');
    const them = parts.length > 1 ? 'those' : 'it';
    return `Can't delete this template — it's still tied to ${joined}. Void or complete ${them} first, then try again.`;
  }
}
