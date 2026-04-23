import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Organization } from '../../entities/organization.entity';
import { InserviceTraining } from '../entities/inservice-training.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { InserviceCompletionService } from './inservice-completion.service';
import { EmployeeDocumentStorageService } from './employee-document-storage.service';
import { CreateInserviceTrainingDto } from '../dto/create-inservice-training.dto';
import { UpdateInserviceTrainingDto } from '../dto/update-inservice-training.dto';
import { QueryInserviceTrainingDto } from '../dto/query-inservice-training.dto';
import {
  COMPLETION_FREQUENCY_EXPIRY_MONTHS,
  InserviceCompletionFrequency,
} from '../dto/create-inservice-training.dto';

export const INSERVICE_CONTENT_REQUIRED_MESSAGE =
  'Please provide a video link, upload a PDF, or both.';

const MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024; // 50MB

export interface PdfFileEntry {
  file_name: string;
  file_path: string;
  file_size_bytes: number;
  title?: string;
}

export interface InserviceTrainingResponse {
  id: string;
  organization_id: string;
  code: string;
  title: string;
  description: string | null;
  completion_frequency: string;
  expiry_months: number | null;
  pdf_files: PdfFileEntry[];
  video_urls: string[];
  video_titles: string[];
  sort_order: number;
  is_active: boolean;
  has_quiz: boolean;
  passing_score_percent: number | null;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class InserviceTrainingService {
  constructor(
    @InjectRepository(InserviceTraining)
    private readonly inserviceTrainingRepository: Repository<InserviceTraining>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    private readonly organizationRoleService: OrganizationRoleService,
    private readonly inserviceCompletionService: InserviceCompletionService,
    private readonly storageService: EmployeeDocumentStorageService,
  ) {}

  private async ensureAccess(organizationId: string, userId: string): Promise<void> {
    const canAccess = await this.organizationRoleService.hasAnyRoleInOrganization(
      userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (!canAccess) {
      throw new ForbiddenException(
        'You do not have permission to manage inservice trainings in this organization.',
      );
    }

    const organization = await this.organizationRepository.findOne({
      where: { id: organizationId },
    });
    if (!organization) {
      throw new NotFoundException('Organization not found');
    }
  }

  private toResponse(inservice: InserviceTraining): InserviceTrainingResponse {
    return {
      id: inservice.id,
      organization_id: inservice.organization_id,
      code: inservice.code,
      title: inservice.title,
      description: inservice.description,
      completion_frequency: inservice.completion_frequency,
      expiry_months: inservice.expiry_months,
      pdf_files: (inservice.pdf_files ?? []).map((f) => ({
        file_name: f.file_name,
        file_path: f.file_path,
        file_size_bytes: Number(f.file_size_bytes),
        title: f.title,
      })),
      video_urls: inservice.video_urls ?? [],
      video_titles: (() => {
        const urls = inservice.video_urls ?? [];
        const titles = inservice.video_titles ?? [];
        return urls.map((_, i) => titles[i] ?? '');
      })(),
      sort_order: inservice.sort_order,
      is_active: inservice.is_active,
      has_quiz: inservice.has_quiz,
      passing_score_percent: inservice.passing_score_percent,
      created_at: inservice.created_at,
      updated_at: inservice.updated_at,
    };
  }

  private hasContent(inservice: InserviceTraining): boolean {
    return !!(inservice.pdf_files?.length || inservice.video_urls?.length);
  }

  async findAll(
    organizationId: string,
    queryDto: QueryInserviceTrainingDto,
    userId: string,
  ): Promise<{
    data: InserviceTrainingResponse[];
    total: number;
    page: number;
    limit: number;
  }> {
    await this.ensureAccess(organizationId, userId);

    const { page = 1, limit = 20, search, completion_frequency, is_active } = queryDto;
    const skip = (page - 1) * limit;

    const qb = this.inserviceTrainingRepository
      .createQueryBuilder('it')
      .where('it.organization_id = :organizationId', { organizationId });

    if (search && search.trim()) {
      qb.andWhere('(it.code ILIKE :search OR it.title ILIKE :search)', {
        search: `%${search.trim()}%`,
      });
    }
    if (completion_frequency) {
      qb.andWhere('it.completion_frequency = :completion_frequency', {
        completion_frequency,
      });
    }
    if (is_active !== undefined) {
      qb.andWhere('it.is_active = :is_active', { is_active });
    }

    qb.orderBy('it.sort_order', 'ASC').addOrderBy('it.created_at', 'DESC');

    const [list, total] = await qb.skip(skip).take(limit).getManyAndCount();

    return {
      data: list.map((it) => this.toResponse(it)),
      total,
      page,
      limit,
    };
  }

  async findOne(
    organizationId: string,
    id: string,
    userId: string,
  ): Promise<InserviceTrainingResponse> {
    await this.ensureAccess(organizationId, userId);

    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }
    return this.toResponse(inservice);
  }

  /**
   * Resolves inservice by id and ensures the user has access (admin role or employee with access via requirement tags).
   * Use for routes that only have inserviceId in path (e.g. quiz-questions).
   */
  async ensureInserviceAccess(inserviceId: string, _userId: string): Promise<InserviceTraining> {
    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id: inserviceId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }
    return inservice;
  }

  /** Updates has_quiz flag (used when first/last quiz question is added/removed). */
  async setHasQuiz(inserviceId: string, hasQuiz: boolean): Promise<void> {
    await this.inserviceTrainingRepository.update(inserviceId, {
      has_quiz: hasQuiz,
    });
  }

  /** Updates passing_score_percent (used when quiz is enabled). */
  async setPassingScore(inserviceId: string, passingScorePercent: number | null): Promise<void> {
    await this.inserviceTrainingRepository.update(inserviceId, {
      passing_score_percent: passingScorePercent,
    });
  }

  async presignUpload(
    organizationId: string,
    inserviceIdOrNew: string,
    filename: string,
    contentType: string,
    userId: string,
  ): Promise<{ uploadUrl: string; key: string; expiresIn: number }> {
    await this.ensureAccess(organizationId, userId);
    return this.storageService.presignUploadForInserviceDocument(
      organizationId,
      inserviceIdOrNew,
      filename,
      contentType,
    );
  }

  async create(
    organizationId: string,
    dto: CreateInserviceTrainingDto,
    userId: string,
    pdfFiles?: PdfFileEntry[],
  ): Promise<InserviceTrainingResponse> {
    await this.ensureAccess(organizationId, userId);

    const videoUrls = (dto.video_urls ?? []).map((u) => u.trim()).filter(Boolean);
    const validPdfFiles = (pdfFiles ?? []).filter((f) => f.file_path && f.file_name);
    if (!videoUrls.length && !validPdfFiles.length) {
      throw new BadRequestException(INSERVICE_CONTENT_REQUIRED_MESSAGE);
    }

    for (const f of validPdfFiles) {
      if (f.file_size_bytes > MAX_PDF_SIZE_BYTES) {
        throw new BadRequestException('Each PDF must be 50MB or less');
      }
      const exists = await this.storageService.verifyUploaded(f.file_path);
      if (!exists) {
        throw new BadRequestException(`Uploaded file not found in storage: ${f.file_name}`);
      }
    }

    const existing = await this.inserviceTrainingRepository.findOne({
      where: { organization_id: organizationId, code: dto.code },
    });
    if (existing) {
      throw new ConflictException(
        `An inservice training with code "${dto.code}" already exists in this organization.`,
      );
    }

    const frequency = dto.completion_frequency;
    const expiryMonths = COMPLETION_FREQUENCY_EXPIRY_MONTHS[frequency] ?? null;

    const videoTitles = (dto.video_titles ?? []).map((t) => (t ?? '').trim());
    const alignedVideoTitles = videoUrls.map((_, i) => videoTitles[i] ?? '');

    const fileTitles = (dto.file_titles ?? []).map((t) => (t ?? '').trim());
    const pdfFilesWithTitles: PdfFileEntry[] = validPdfFiles.map((f, i) => {
      const entry: PdfFileEntry = {
        file_name: f.file_name,
        file_path: f.file_path,
        file_size_bytes: f.file_size_bytes,
      };
      const t = fileTitles[i];
      if (t) entry.title = t;
      return entry;
    });

    const inservice = this.inserviceTrainingRepository.create({
      organization_id: organizationId,
      code: dto.code,
      title: dto.title,
      description: dto.description ?? null,
      completion_frequency: dto.completion_frequency,
      expiry_months: expiryMonths,
      video_urls: videoUrls,
      video_titles: alignedVideoTitles,
      pdf_files: pdfFilesWithTitles,
      sort_order: dto.sort_order ?? 0,
      is_active: true,
      has_quiz: dto.has_quiz ?? false,
      passing_score_percent: dto.passing_score_percent != null ? dto.passing_score_percent : null,
    });

    const saved = await this.inserviceTrainingRepository.save(inservice);
    return this.toResponse(saved);
  }

  async update(
    organizationId: string,
    id: string,
    dto: UpdateInserviceTrainingDto,
    userId: string,
    newPdfFiles?: PdfFileEntry[],
  ): Promise<InserviceTrainingResponse> {
    await this.ensureAccess(organizationId, userId);

    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }

    const validNewPdfFiles = (newPdfFiles ?? []).filter((f) => f.file_path && f.file_name);
    for (const f of validNewPdfFiles) {
      if (f.file_size_bytes > MAX_PDF_SIZE_BYTES) {
        throw new BadRequestException('Each PDF must be 50MB or less');
      }
      const exists = await this.storageService.verifyUploaded(f.file_path);
      if (!exists) {
        throw new BadRequestException(`Uploaded file not found in storage: ${f.file_name}`);
      }
    }

    if (dto.title !== undefined) inservice.title = dto.title;
    if (dto.description !== undefined) inservice.description = dto.description;
    if (dto.completion_frequency !== undefined) {
      inservice.completion_frequency = dto.completion_frequency;
      const freq = dto.completion_frequency as InserviceCompletionFrequency;
      inservice.expiry_months = COMPLETION_FREQUENCY_EXPIRY_MONTHS[freq] ?? null;
    }
    if (dto.video_urls !== undefined) {
      const trimmedUrls: string[] = [];
      const alignedTitles: string[] = [];
      const incomingTitles = dto.video_titles ?? [];
      dto.video_urls.forEach((u, i) => {
        const trimmed = u.trim();
        if (!trimmed) return;
        trimmedUrls.push(trimmed);
        alignedTitles.push((incomingTitles[i] ?? '').trim());
      });
      inservice.video_urls = trimmedUrls;
      inservice.video_titles = alignedTitles;
    } else if (dto.video_titles !== undefined) {
      const urls = inservice.video_urls ?? [];
      inservice.video_titles = urls.map((_, i) => (dto.video_titles?.[i] ?? '').trim());
    }
    if (dto.sort_order !== undefined) inservice.sort_order = dto.sort_order;
    if (dto.is_active !== undefined) inservice.is_active = dto.is_active;
    if (dto.has_quiz !== undefined) inservice.has_quiz = dto.has_quiz;
    if (dto.passing_score_percent !== undefined) {
      inservice.passing_score_percent =
        dto.passing_score_percent == null ? null : dto.passing_score_percent;
    }

    let pdfFiles = [...(inservice.pdf_files ?? [])];

    if (dto.remove_file_paths?.length) {
      const toRemove = new Set(dto.remove_file_paths);
      const removed = pdfFiles.filter((f) => toRemove.has(f.file_path));
      pdfFiles = pdfFiles.filter((f) => !toRemove.has(f.file_path));
      for (const r of removed) {
        await this.storageService.deleteInserviceDocument(r.file_path);
      }
    }

    if (dto.existing_file_titles?.length) {
      const titleByPath = new Map<string, string>();
      for (const e of dto.existing_file_titles) {
        titleByPath.set(e.file_path, (e.title ?? '').trim());
      }
      pdfFiles = pdfFiles.map((f) => {
        if (!titleByPath.has(f.file_path)) return f;
        const t = titleByPath.get(f.file_path) ?? '';
        return t ? { ...f, title: t } : { ...f, title: undefined };
      });
    }

    if (validNewPdfFiles.length) {
      const fileTitles = (dto.file_titles ?? []).map((t) => (t ?? '').trim());
      const newEntries: PdfFileEntry[] = validNewPdfFiles.map((f, i) => {
        const entry: PdfFileEntry = {
          file_name: f.file_name,
          file_path: f.file_path,
          file_size_bytes: f.file_size_bytes,
        };
        const t = fileTitles[i];
        if (t) entry.title = t;
        return entry;
      });
      pdfFiles = [...pdfFiles, ...newEntries];
    }

    inservice.pdf_files = pdfFiles;

    if (!inservice.pdf_files?.length && !inservice.video_urls?.length) {
      throw new BadRequestException(INSERVICE_CONTENT_REQUIRED_MESSAGE);
    }

    await this.inserviceTrainingRepository.save(inservice);
    return this.toResponse(inservice);
  }

  async remove(organizationId: string, id: string, userId: string): Promise<void> {
    await this.ensureAccess(organizationId, userId);

    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }

    await this.inserviceTrainingRepository.remove(inservice);
  }

  async getPdfFileUrl(
    organizationId: string,
    id: string,
    _userId: string,
    fileIndex: number,
  ): Promise<{ url: string; file_name: string }> {
    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }

    const files = inservice.pdf_files ?? [];
    if (!files.length) {
      throw new NotFoundException('This inservice has no PDF documents');
    }
    if (fileIndex < 0 || fileIndex >= files.length) {
      throw new NotFoundException(`File index ${fileIndex} is out of range (0-${files.length - 1})`);
    }

    const entry = files[fileIndex];
    const url = await this.storageService.getPresignedViewUrl(entry.file_path);
    return { url, file_name: entry.file_name };
  }
}
