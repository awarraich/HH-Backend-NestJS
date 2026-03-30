import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CompetencyTemplate } from '../entities/competency-template.entity';
import { CreateTemplateDto } from '../dto/create-template.dto';
import { UpdateTemplateDto } from '../dto/update-template.dto';
import { PdfStorageService } from './pdf-storage.service';

@Injectable()
export class TemplatesService {
  constructor(
    @InjectRepository(CompetencyTemplate)
    private readonly repo: Repository<CompetencyTemplate>,
    private readonly pdfStorage: PdfStorageService,
  ) {}

  async findAll(orgId: string, mode?: 'grid' | 'document') {
    const where: any = { organization_id: orgId };
    if (mode) where.mode = mode;
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

  async getPdfStream(orgId: string, id: string) {
    const t = await this.repo.findOne({ where: { id, organization_id: orgId } });
    if (!t || !t.pdf_file_key) throw new NotFoundException('PDF not found');
    const { stream, contentType } = await this.pdfStorage.getFileStream(
      t.pdf_file_key,
      t.pdf_original_name ?? 'document.pdf',
    );
    return { stream, contentType, fileName: t.pdf_original_name ?? 'document.pdf' };
  }

  buildPdfUrl(orgId: string, templateId: string): string {
    return `/v1/api/organizations/${orgId}/document-workflow/templates/${templateId}/pdf/view`;
  }

  async create(orgId: string, dto: CreateTemplateDto, userId: string) {
    return this.repo.save(
      this.repo.create({
        organization_id: orgId,
        name: dto.name,
        description: dto.description ?? '',
        mode: dto.mode,
        layout: dto.layout ?? { rows: 3, cols: 3, cells: [[]] },
        document_fields: dto.documentFields ?? [],
        roles: dto.roles ?? [],
        created_by: userId,
      }),
    );
  }

  async update(orgId: string, id: string, dto: UpdateTemplateDto) {
    const t = await this.findOne(orgId, id);
    if (dto.name !== undefined) t.name = dto.name;
    if (dto.description !== undefined) t.description = dto.description;
    if (dto.mode !== undefined) t.mode = dto.mode;
    if (dto.layout !== undefined) t.layout = dto.layout;
    if (dto.documentFields !== undefined) t.document_fields = dto.documentFields;
    if (dto.roles !== undefined) t.roles = dto.roles;
    return this.repo.save(t);
  }

  async uploadPdf(orgId: string, id: string, buffer: Buffer, originalFilename: string, fileSize: number) {
    const t = await this.findOne(orgId, id);
    if (t.pdf_file_key) {
      await this.pdfStorage.delete(t.pdf_file_key);
    }
    const result = await this.pdfStorage.upload(buffer, originalFilename, orgId, id);
    t.pdf_file_key = result.file_key;
    t.pdf_original_name = result.original_name;
    t.pdf_size_bytes = fileSize;
    return this.repo.save(t);
  }

  async delete(orgId: string, id: string) {
    const t = await this.findOne(orgId, id);
    if (t.pdf_file_key) {
      await this.pdfStorage.delete(t.pdf_file_key);
    }
    await this.repo.remove(t);
  }
}
