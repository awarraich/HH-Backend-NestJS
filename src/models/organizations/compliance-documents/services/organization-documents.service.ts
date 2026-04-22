import { BadRequestException, Injectable, NotFoundException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, IsNull, Repository } from 'typeorm';
import { extractText, getDocumentProxy } from 'unpdf';
import { OrganizationDocument } from '../entities/organization-document.entity';
import { OrganizationDocumentChunk } from '../entities/organization-document-chunk.entity';
import { OrganizationDocumentCategory } from '../entities/organization-document-category.entity';
import { EmbeddingService } from '../../../../common/services/embedding/embedding.service';
import { OrganizationDocumentStorageService } from './organization-document-storage.service';
import { S3Service } from '../../../../common/services/s3/s3.service';
import { CreateOrganizationDocumentDto } from '../dto/create-organization-document.dto';
import { UpdateOrganizationDocumentDto } from '../dto/update-organization-document.dto';
import { QueryOrganizationDocumentDto } from '../dto/query-organization-document.dto';
import {
  OrganizationDocumentSerializer,
  computeDocumentStatus,
  computeDaysUntilExpiration,
} from '../serializers/organization-document.serializer';

const VECTOR_SEARCH_LIMIT = 10;
const MAX_EMBEDDING_TEXT_LENGTH = 8000;
const CHUNK_SIZE = 1000;
const CHUNK_OVERLAP = 200;

@Injectable()
export class OrganizationDocumentsService {
  private readonly logger = new Logger(OrganizationDocumentsService.name);
  private readonly serializer = new OrganizationDocumentSerializer();

  constructor(
    @InjectRepository(OrganizationDocument)
    private readonly documentRepository: Repository<OrganizationDocument>,
    @InjectRepository(OrganizationDocumentChunk)
    private readonly chunkRepository: Repository<OrganizationDocumentChunk>,
    @InjectRepository(OrganizationDocumentCategory)
    private readonly categoryRepository: Repository<OrganizationDocumentCategory>,
    private readonly embeddingService: EmbeddingService,
    private readonly storageService: OrganizationDocumentStorageService,
    private readonly s3Service: S3Service,
    private readonly dataSource: DataSource,
  ) {}

  async presignUpload(
    organizationId: string,
    filename: string,
    contentType: string,
  ): Promise<{ uploadUrl: string; key: string; expiresIn: number }> {
    return this.storageService.presignUpload(organizationId, filename, contentType);
  }

  async findAll(organizationId: string, query: QueryOrganizationDocumentDto) {
    const { search, category_id, status, sort_by, sort_order, page = 1, limit = 20 } = query;
    const skip = (page - 1) * limit;

    const qb = this.documentRepository
      .createQueryBuilder('doc')
      .leftJoinAndSelect('doc.category', 'category')
      .leftJoinAndSelect('doc.uploadedByUser', 'uploader')
      .where('doc.organization_id = :organizationId', { organizationId })
      .andWhere('doc.deleted_at IS NULL');

    if (search) {
      qb.andWhere('doc.document_name ILIKE :search', { search: `%${search}%` });
    }
    if (category_id) {
      qb.andWhere('doc.category_id = :category_id', { category_id });
    }

    const sortColumn =
      sort_by === 'category'
        ? 'category.name'
        : sort_by === 'document_name'
          ? 'doc.document_name'
          : sort_by === 'expiration_date'
            ? 'doc.expiration_date'
            : 'doc.created_at';
    qb.orderBy(sortColumn, sort_order === 'asc' ? 'ASC' : 'DESC');

    const [allDocs, total] = await qb.getManyAndCount();

    let filtered = allDocs;
    if (status) {
      filtered = allDocs.filter((d) => {
        const s = computeDocumentStatus(d);
        if (status === 'missing') return s === 'no_expiration';
        return s === status;
      });
    }

    const paged = filtered.slice(skip, skip + limit);
    return {
      data: this.serializer.serializeMany(paged),
      total: status ? filtered.length : total,
      page,
      limit,
    };
  }

  async getStats(organizationId: string) {
    const docs = await this.documentRepository.find({
      where: { organization_id: organizationId, deleted_at: IsNull() },
      relations: ['category'],
    });

    let valid = 0;
    let expiringSoon = 0;
    let expired = 0;
    let missing = 0;

    for (const doc of docs) {
      const s = computeDocumentStatus(doc);
      if (s === 'valid') valid++;
      else if (s === 'expiring_soon') expiringSoon++;
      else if (s === 'expired') expired++;
      else missing++;
    }

    const categoryMap = new Map<string, { category_id: string; category_name: string; count: number }>();
    for (const doc of docs) {
      const key = doc.category_id;
      if (!categoryMap.has(key)) {
        categoryMap.set(key, {
          category_id: key,
          category_name: doc.category?.name ?? 'Unknown',
          count: 0,
        });
      }
      categoryMap.get(key)!.count++;
    }

    return {
      total: docs.length,
      valid,
      expiring_soon: expiringSoon,
      expired,
      missing,
      by_category: Array.from(categoryMap.values()),
    };
  }

  async findOne(organizationId: string, documentId: string) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
      relations: ['category', 'uploadedByUser'],
    });
    if (!doc) throw new NotFoundException('Document not found');
    return this.serializer.serialize(doc);
  }

  async confirmUpload(
    organizationId: string,
    dto: CreateOrganizationDocumentDto,
    payload: { key: string; fileName: string; mimeType?: string; sizeBytes?: number },
    userId: string,
  ) {
    const category = await this.categoryRepository.findOne({
      where: { id: dto.category_id, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!category) throw new NotFoundException('Category not found');

    const exists = await this.storageService.verifyUploaded(payload.key);
    if (!exists) {
      throw new BadRequestException('Uploaded file not found in storage. Retry the upload.');
    }

    const doc = this.documentRepository.create({
      organization_id: organizationId,
      category_id: dto.category_id,
      document_name: dto.document_name,
      file_name: payload.fileName,
      file_path: payload.key,
      file_size_bytes: payload.sizeBytes ?? null,
      mime_type: payload.mimeType ?? null,
      is_required: dto.is_required ?? false,
      has_expiration: dto.has_expiration ?? false,
      expiration_date: dto.expiration_date ? new Date(dto.expiration_date) : null,
      uploaded_by: userId,
      created_by: userId,
      updated_by: userId,
      extraction_status: 'pending',
    });

    const saved = await this.documentRepository.save(doc);

    this.runExtractionAndChunking(saved.id).catch((err) => {
      this.logger.warn(`Extraction failed for compliance document ${saved.id}`, err);
    });

    const full = await this.documentRepository.findOne({
      where: { id: saved.id },
      relations: ['category', 'uploadedByUser'],
    });
    return this.serializer.serialize(full!);
  }

  async update(
    organizationId: string,
    documentId: string,
    dto: UpdateOrganizationDocumentDto,
    userId: string,
  ) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!doc) throw new NotFoundException('Document not found');

    if (dto.document_name !== undefined) doc.document_name = dto.document_name;
    if (dto.category_id !== undefined) {
      const category = await this.categoryRepository.findOne({
        where: { id: dto.category_id, organization_id: organizationId, deleted_at: IsNull() },
      });
      if (!category) throw new NotFoundException('Category not found');
      doc.category_id = dto.category_id;
    }
    if (dto.is_required !== undefined) doc.is_required = dto.is_required;
    if (dto.has_expiration !== undefined) doc.has_expiration = dto.has_expiration;
    if (dto.expiration_date !== undefined) {
      doc.expiration_date = dto.expiration_date ? new Date(dto.expiration_date) : null;
    }
    doc.updated_by = userId;

    const saved = await this.documentRepository.save(doc);
    const full = await this.documentRepository.findOne({
      where: { id: saved.id },
      relations: ['category', 'uploadedByUser'],
    });
    return this.serializer.serialize(full!);
  }

  async replaceFile(
    organizationId: string,
    documentId: string,
    payload: { key: string; fileName: string; mimeType?: string; sizeBytes?: number },
    userId: string,
  ) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!doc) throw new NotFoundException('Document not found');

    const exists = await this.storageService.verifyUploaded(payload.key);
    if (!exists) {
      throw new BadRequestException('Uploaded file not found in storage. Retry the upload.');
    }

    const previousKey = doc.file_path;

    doc.file_name = payload.fileName;
    doc.file_path = payload.key;
    doc.file_size_bytes = payload.sizeBytes ?? null;
    doc.mime_type = payload.mimeType ?? null;
    doc.uploaded_by = userId;
    doc.updated_by = userId;
    doc.extracted_text = null;
    doc.extraction_status = 'pending';
    doc.extraction_error = null;

    const saved = await this.documentRepository.save(doc);

    if (previousKey && previousKey !== payload.key) {
      this.storageService.delete(previousKey).catch((err) => {
        this.logger.warn(`Failed to delete previous file ${previousKey}`, err);
      });
    }

    this.runExtractionAndChunking(saved.id).catch((err) => {
      this.logger.warn(`Extraction failed for compliance document ${saved.id}`, err);
    });

    const full = await this.documentRepository.findOne({
      where: { id: saved.id },
      relations: ['category', 'uploadedByUser'],
    });
    return this.serializer.serialize(full!);
  }

  async remove(organizationId: string, documentId: string, userId: string) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!doc) throw new NotFoundException('Document not found');

    doc.deleted_at = new Date();
    doc.updated_by = userId;
    await this.documentRepository.save(doc);
  }

  async getDownloadUrl(organizationId: string, documentId: string) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!doc) throw new NotFoundException('Document not found');

    const url = await this.storageService.getPresignedViewUrl(doc.file_path);
    return { url, file_name: doc.file_name, mime_type: doc.mime_type };
  }

  async scanDocument(organizationId: string, documentId: string) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!doc) throw new NotFoundException('Document not found');

    await this.runExtractionAndChunking(doc.id);

    const updated = await this.documentRepository.findOne({ where: { id: doc.id } });
    const chunkCount = await this.chunkRepository.count({ where: { document_id: doc.id } });

    return {
      extraction_status: updated?.extraction_status ?? 'unknown',
      chunk_count: chunkCount,
    };
  }

  async semanticSearch(
    organizationId: string,
    queryText: string,
    categoryId?: string,
    limit?: number,
    documentIds?: string[],
  ) {
    const searchLimit = limit ?? VECTOR_SEARCH_LIMIT;
    const queryEmbedding = await this.embeddingService.embed(queryText.trim());
    if (!queryEmbedding?.length) {
      return { results: [], total_results: 0 };
    }

    const vectorStr = `[${queryEmbedding.join(',')}]`;

    let sql = `
      SELECT c.id, c.document_id, c.chunk_text, c.chunk_index,
             d.document_name, cat.name AS category_name,
             (c.embedding <=> $1::vector) AS distance
      FROM organization_document_chunks c
      JOIN organization_documents d ON d.id = c.document_id
      JOIN organization_document_categories cat ON cat.id = d.category_id
      WHERE c.organization_id = $2
        AND c.embedding IS NOT NULL
        AND d.deleted_at IS NULL
    `;
    const params: unknown[] = [vectorStr, organizationId];

    if (documentIds?.length) {
      sql += ` AND c.document_id = ANY($${params.length + 1}::uuid[])`;
      params.push(documentIds);
    }

    if (categoryId) {
      sql += ` AND d.category_id = $${params.length + 1}`;
      params.push(categoryId);
    }

    sql += ` ORDER BY c.embedding <=> $1::vector LIMIT $${params.length + 1}`;
    params.push(searchLimit);

    const rows: Array<{
      id: string;
      document_id: string;
      chunk_text: string;
      chunk_index: number;
      document_name: string;
      category_name: string;
      distance: number;
    }> = await this.dataSource.query(sql, params);

    return {
      results: rows.map((r) => ({
        document_id: r.document_id,
        document_name: r.document_name,
        category_name: r.category_name,
        snippet: r.chunk_text.slice(0, 300) + (r.chunk_text.length > 300 ? '...' : ''),
        similarity_score: Math.round((1 - r.distance) * 100) / 100,
        chunk_index: r.chunk_index,
      })),
      total_results: rows.length,
    };
  }

  async getDocumentDetails(organizationId: string, documentId: string) {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
      relations: ['category'],
    });
    if (!doc) throw new NotFoundException('Document not found');

    return {
      id: doc.id,
      document_name: doc.document_name,
      category: doc.category?.name ?? 'Unknown',
      status: computeDocumentStatus(doc),
      expiration_date: doc.expiration_date,
      days_until_expiration: computeDaysUntilExpiration(doc),
      is_required: doc.is_required,
      file_name: doc.file_name,
      extracted_text: doc.extracted_text,
      extraction_status: doc.extraction_status,
      created_at: doc.created_at,
      updated_at: doc.updated_at,
    };
  }

  async getExpiringDocuments(organizationId: string, daysAhead: number = 90) {
    const docs = await this.documentRepository.find({
      where: { organization_id: organizationId, deleted_at: IsNull() },
      relations: ['category'],
    });

    const alerts: Array<{
      priority: 'critical' | 'warning' | 'info';
      document_id: string;
      document_name: string;
      category: string;
      status: string;
      expiration_date: Date | null;
      days_overdue?: number;
      days_remaining?: number;
      action: string;
    }> = [];

    let critical = 0;
    let warning = 0;
    let missingRequired = 0;

    for (const doc of docs) {
      const status = computeDocumentStatus(doc);
      const days = computeDaysUntilExpiration(doc);

      if (status === 'expired') {
        critical++;
        alerts.push({
          priority: 'critical',
          document_id: doc.id,
          document_name: doc.document_name,
          category: doc.category?.name ?? 'Unknown',
          status,
          expiration_date: doc.expiration_date,
          days_overdue: days != null ? Math.abs(days) : undefined,
          action: `Renew immediately — expired ${days != null ? Math.abs(days) : '?'} days ago`,
        });
      } else if (status === 'expiring_soon') {
        warning++;
        alerts.push({
          priority: 'warning',
          document_id: doc.id,
          document_name: doc.document_name,
          category: doc.category?.name ?? 'Unknown',
          status,
          expiration_date: doc.expiration_date,
          days_remaining: days ?? undefined,
          action: `Renewal due in ${days} days`,
        });
      } else if (status === 'valid' && days != null && days <= daysAhead) {
        alerts.push({
          priority: 'info',
          document_id: doc.id,
          document_name: doc.document_name,
          category: doc.category?.name ?? 'Unknown',
          status,
          expiration_date: doc.expiration_date,
          days_remaining: days,
          action: `Expires in ${days} days — plan renewal`,
        });
      }

      if (doc.is_required && status === 'no_expiration') {
        missingRequired++;
      }
    }

    alerts.sort((a, b) => {
      const priorityOrder = { critical: 0, warning: 1, info: 2 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

    return {
      alerts,
      summary: { critical, warning, missing_required: missingRequired },
    };
  }

  private async runExtractionAndChunking(documentId: string): Promise<void> {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, deleted_at: IsNull() },
      relations: ['category'],
    });
    if (!doc) return;

    try {
      const buffer = await this.s3Service.getObjectAsBuffer(doc.file_path);

      let extractedText = '';
      const mime = (doc.mime_type ?? '').toLowerCase();
      if (mime.includes('pdf') || doc.file_name.toLowerCase().endsWith('.pdf')) {
        try {
          const pdf = await getDocumentProxy(new Uint8Array(buffer));
          const result = await extractText(pdf, { mergePages: true });
          extractedText = result?.text?.trim() ?? '';
        } catch (e) {
          doc.extraction_error = e instanceof Error ? e.message : String(e);
          doc.extraction_status = 'failed';
          await this.documentRepository.save(doc);
          return;
        }
      }

      doc.extracted_text = extractedText || null;
      doc.extraction_status = 'completed';
      doc.extraction_error = null;
      await this.documentRepository.save(doc);

      await this.chunkRepository.delete({ document_id: documentId });

      if (!extractedText) return;

      const chunks: string[] = [];
      for (let i = 0; i < extractedText.length; i += CHUNK_SIZE - CHUNK_OVERLAP) {
        const slice = extractedText.slice(i, i + CHUNK_SIZE);
        if (slice.trim()) chunks.push(slice.trim());
      }

      for (let i = 0; i < chunks.length; i++) {
        const text = chunks[i].slice(0, MAX_EMBEDDING_TEXT_LENGTH);
        const embedding = await this.embeddingService.embed(text);
        if (!embedding?.length) continue;

        const vectorStr = `[${embedding.join(',')}]`;
        await this.dataSource.query(
          `INSERT INTO organization_document_chunks
           (id, document_id, organization_id, chunk_index, chunk_text, chunk_tokens, metadata, embedding)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, NULL, $5, $6::vector)`,
          [
            documentId,
            doc.organization_id,
            i,
            chunks[i],
            JSON.stringify({
              category_name: doc.category?.name,
              document_name: doc.document_name,
            }),
            vectorStr,
          ],
        );
      }
    } catch (err) {
      doc.extraction_error = err instanceof Error ? err.message : String(err);
      doc.extraction_status = 'failed';
      await this.documentRepository.save(doc);
    }
  }
}
