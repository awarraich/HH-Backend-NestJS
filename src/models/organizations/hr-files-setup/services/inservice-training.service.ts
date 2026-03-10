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

export interface InserviceTrainingResponse {
  id: string;
  organization_id: string;
  code: string;
  title: string;
  description: string | null;
  completion_frequency: string;
  expiry_months: number | null;
  pdf_file_name: string | null;
  pdf_file_path: string | null;
  pdf_file_size_bytes: number | null;
  video_url: string | null;
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
      pdf_file_name: inservice.pdf_file_name,
      pdf_file_path: inservice.pdf_file_path,
      pdf_file_size_bytes: inservice.pdf_file_size_bytes
        ? Number(inservice.pdf_file_size_bytes)
        : null,
      video_url: inservice.video_url,
      sort_order: inservice.sort_order,
      is_active: inservice.is_active,
      has_quiz: inservice.has_quiz,
      passing_score_percent: inservice.passing_score_percent,
      created_at: inservice.created_at,
      updated_at: inservice.updated_at,
    };
  }

  private hasContent(inservice: InserviceTraining): boolean {
    return !!(inservice.pdf_file_path || inservice.video_url);
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
   * Resolves inservice by id and ensures the user has access to its organization.
   * Use for routes that only have inserviceId in path (e.g. quiz-questions).
   */
  async ensureInserviceAccess(inserviceId: string, userId: string): Promise<InserviceTraining> {
    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id: inserviceId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }
    await this.ensureAccess(inservice.organization_id, userId);
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

  async create(
    organizationId: string,
    dto: CreateInserviceTrainingDto,
    userId: string,
    file?: { buffer: Buffer; originalFilename: string },
  ): Promise<InserviceTrainingResponse> {
    await this.ensureAccess(organizationId, userId);

    const hasVideo = !!dto.video_url?.trim();
    const hasPdf = !!file?.buffer?.length;
    if (!hasVideo && !hasPdf) {
      throw new BadRequestException(INSERVICE_CONTENT_REQUIRED_MESSAGE);
    }

    if (file && file.buffer.length > MAX_PDF_SIZE_BYTES) {
      throw new BadRequestException('PDF must be 50MB or less');
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

    const inservice = this.inserviceTrainingRepository.create({
      organization_id: organizationId,
      code: dto.code,
      title: dto.title,
      description: dto.description ?? null,
      completion_frequency: dto.completion_frequency,
      expiry_months: expiryMonths,
      video_url: dto.video_url?.trim() || null,
      sort_order: dto.sort_order ?? 0,
      is_active: true,
      has_quiz: dto.has_quiz ?? false,
      passing_score_percent: dto.passing_score_percent != null ? dto.passing_score_percent : null,
    });

    // When we have a PDF we need to save first to get id, then upload. Use placeholder so DB CHECK passes.
    if (hasPdf) {
      inservice.pdf_file_path = 'pending';
      inservice.pdf_file_name = file.originalFilename;
    }

    const saved = await this.inserviceTrainingRepository.save(inservice);

    if (hasPdf && file) {
      const { file_name, file_path } = await this.storageService.saveInserviceDocument(
        file.buffer,
        file.originalFilename,
        organizationId,
        saved.id,
      );
      saved.pdf_file_name = file_name;
      saved.pdf_file_path = file_path;
      saved.pdf_file_size_bytes = file.buffer.length;
      await this.inserviceTrainingRepository.save(saved);
    }

    return this.toResponse(saved);
  }

  async update(
    organizationId: string,
    id: string,
    dto: UpdateInserviceTrainingDto,
    userId: string,
    file?: { buffer: Buffer; originalFilename: string },
  ): Promise<InserviceTrainingResponse> {
    await this.ensureAccess(organizationId, userId);

    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }

    if (file?.buffer?.length && file.buffer.length > MAX_PDF_SIZE_BYTES) {
      throw new BadRequestException('PDF must be 50MB or less');
    }

    if (dto.title !== undefined) inservice.title = dto.title;
    if (dto.description !== undefined) inservice.description = dto.description;
    if (dto.completion_frequency !== undefined) {
      inservice.completion_frequency = dto.completion_frequency;
      const freq = dto.completion_frequency as InserviceCompletionFrequency;
      inservice.expiry_months = COMPLETION_FREQUENCY_EXPIRY_MONTHS[freq] ?? null;
    }
    if (dto.video_url !== undefined) {
      inservice.video_url =
        dto.video_url === '' || dto.video_url === null ? null : dto.video_url.trim();
    }
    if (dto.sort_order !== undefined) inservice.sort_order = dto.sort_order;
    if (dto.is_active !== undefined) inservice.is_active = dto.is_active;
    if (dto.has_quiz !== undefined) inservice.has_quiz = dto.has_quiz;
    if (dto.passing_score_percent !== undefined) {
      inservice.passing_score_percent =
        dto.passing_score_percent == null ? null : dto.passing_score_percent;
    }

    if (file?.buffer?.length) {
      const { file_name, file_path } = await this.storageService.saveInserviceDocument(
        file.buffer,
        file.originalFilename,
        organizationId,
        inservice.id,
      );
      inservice.pdf_file_name = file_name;
      inservice.pdf_file_path = file_path;
      inservice.pdf_file_size_bytes = file.buffer.length;
    }

    const hasPdf = !!inservice.pdf_file_path;
    const hasVideo = !!inservice.video_url?.trim();
    if (!hasPdf && !hasVideo) {
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

  /**
   * Returns read stream and content type for inservice PDF. Throws if not found or no PDF.
   */
  async getPdfStream(
    organizationId: string,
    id: string,
    userId: string,
  ): Promise<{
    stream: NodeJS.ReadableStream;
    contentType: string;
    file_name: string;
  }> {
    await this.ensureAccess(organizationId, userId);

    const inservice = await this.inserviceTrainingRepository.findOne({
      where: { id, organization_id: organizationId },
    });
    if (!inservice) {
      throw new NotFoundException('Inservice training not found');
    }
    if (!inservice.pdf_file_path || !inservice.pdf_file_name) {
      throw new NotFoundException('This inservice has no PDF document');
    }

    const { stream, contentType } = await this.storageService.getFileStream(
      inservice.pdf_file_path,
      inservice.pdf_file_name,
    );
    return { stream, contentType, file_name: inservice.pdf_file_name };
  }
}
