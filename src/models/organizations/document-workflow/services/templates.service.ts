import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { CompetencyTemplate } from '../entities/competency-template.entity';
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
    @InjectRepository(DocumentFieldValue)
    private readonly fieldValueRepo: Repository<DocumentFieldValue>,
    @InjectRepository(DocumentWorkflowRole)
    private readonly roleRepo: Repository<DocumentWorkflowRole>,
    private readonly pdfStorage: PdfStorageService,
    private readonly s3Service: S3Service,
  ) {}

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
    return this.repo.save(
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
      this.pdfStorage.delete(previousKey).catch(() => {});
    }
    return saved;
  }

  async delete(orgId: string, id: string) {
    const t = await this.findOne(orgId, id);
    if (t.pdf_file_key) {
      await this.pdfStorage.delete(t.pdf_file_key);
    }
    await this.repo.remove(t);
  }
}
