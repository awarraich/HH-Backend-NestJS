import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, In, IsNull, type FindOptionsWhere, Repository } from 'typeorm';
import OpenAI from 'openai';
import { extractText, getDocumentProxy } from 'unpdf';
import { EmployeeDocument } from '../entities/employee-document.entity';
import { DocumentChunk } from '../entities/document-chunk.entity';
import { HrDocumentType } from '../entities/hr-document-type.entity';
import { EmployeeRequirementTag } from '../entities/employee-requirement-tag.entity';
import { RequirementDocumentType } from '../entities/requirement-document-type.entity';
import { RequirementInserviceTraining } from '../entities/requirement-inservice-training.entity';
import { InserviceTraining } from '../entities/inservice-training.entity';
import { Employee } from '../../../employees/entities/employee.entity';
import { Organization } from '../../entities/organization.entity';
import { OrganizationRoleService } from '../../services/organization-role.service';
import { EmbeddingService } from '../../../../common/services/embedding/embedding.service';
import { EmployeeDocumentStorageService } from './employee-document-storage.service';
import { InserviceCompletionService } from './inservice-completion.service';
import { UpdateEmployeeDocumentDto } from '../dto/update-employee-document.dto';

const VECTOR_SEARCH_LIMIT = 10;
const MAX_EMBEDDING_TEXT_LENGTH = 8000;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function filterValidUuids(ids: string[] | undefined): string[] | undefined {
  if (!ids?.length) return undefined;
  const valid = ids.filter((id) => typeof id === 'string' && UUID_REGEX.test(id));
  return valid.length ? valid : undefined;
}

const EXPIRATION_DATE_REGEX =
  /(?:expir(?:ation|es|y)?|valid\s+until|expires?\s+on|renew\s+by|date\s+of\s+expiration|exp\s+date)[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})/gi;

export interface RequiredDocumentItem {
  document_type: {
    id: string;
    code: string;
    name: string;
    has_expiration: boolean;
    category: string | null;
    sort_order: number;
  };
  document: {
    id: string;
    file_name: string;
    file_path: string;
    file_size_bytes: number | null;
    mime_type: string | null;
    extraction_status: string;
    created_at: Date;
  } | null;
}

export type ExpirationStatusType = 'expired' | 'expiring_soon' | 'valid' | 'has_no_expiration_date';

const EXPIRING_SOON_DAYS = 30;

function getExpirationStatusType(
  expirationDate: Date | null,
  expiringSoonDays: number = EXPIRING_SOON_DAYS,
): ExpirationStatusType {
  if (expirationDate == null) return 'has_no_expiration_date';
  const now = new Date();
  if (expirationDate < now) return 'expired';
  const daysUntil = (expirationDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
  if (daysUntil <= expiringSoonDays) return 'expiring_soon';
  return 'valid';
}

export interface ExpirationStatusItem {
  document_id: string;
  is_expired: boolean;
  expiration_date: string | null;
  document_type_name: string;
  status: ExpirationStatusType;
}

export interface ChatSource {
  document_id: string;
  file_name: string;
  snippet: string;
}

function streamToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer) => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

@Injectable()
export class EmployeeDocumentsService {
  private readonly logger = new Logger(EmployeeDocumentsService.name);
  private readonly openai: OpenAI | null = null;

  constructor(
    @InjectRepository(EmployeeDocument)
    private readonly employeeDocumentRepository: Repository<EmployeeDocument>,
    @InjectRepository(DocumentChunk)
    private readonly documentChunkRepository: Repository<DocumentChunk>,
    @InjectRepository(HrDocumentType)
    private readonly hrDocumentTypeRepository: Repository<HrDocumentType>,
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(Organization)
    private readonly organizationRepository: Repository<Organization>,
    @InjectRepository(EmployeeRequirementTag)
    private readonly employeeRequirementTagRepository: Repository<EmployeeRequirementTag>,
    @InjectRepository(RequirementDocumentType)
    private readonly requirementDocumentTypeRepository: Repository<RequirementDocumentType>,
    @InjectRepository(RequirementInserviceTraining)
    private readonly requirementInserviceTrainingRepository: Repository<RequirementInserviceTraining>,
    @InjectRepository(InserviceTraining)
    private readonly inserviceTrainingRepository: Repository<InserviceTraining>,
    private readonly organizationRoleService: OrganizationRoleService,
    private readonly embeddingService: EmbeddingService,
    private readonly storageService: EmployeeDocumentStorageService,
    private readonly configService: ConfigService,
    private readonly dataSource: DataSource,
    private readonly inserviceCompletionService: InserviceCompletionService,
  ) {
    const apiKey = this.configService.get<string>('apiKeys.openai')?.trim();
    if (apiKey) {
      this.openai = new OpenAI({ apiKey });
    }
  }

  private async ensureDocumentAccess(
    organizationId: string,
    employeeId: string,
    userId: string,
  ): Promise<void> {
    const hasRole = await this.organizationRoleService.hasAnyRoleInOrganization(
      userId,
      organizationId,
      ['OWNER', 'HR', 'MANAGER'],
    );
    if (hasRole) return;

    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
    });
    if (!employee) {
      throw new NotFoundException('Employee not found');
    }
    if (employee.user_id !== userId) {
      throw new ForbiddenException(
        "You do not have permission to access this employee's documents.",
      );
    }
  }

  async getRequiredDocuments(
    organizationId: string,
    employeeId: string,
    userId: string,
  ): Promise<RequiredDocumentItem[]> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const docTypes = await this.hrDocumentTypeRepository.find({
      where: { organization_id: organizationId, is_active: true, is_required: true },
      order: { sort_order: 'ASC', id: 'ASC' },
    });

    const documents = await this.employeeDocumentRepository.find({
      where: {
        employee_id: employeeId,
        organization_id: organizationId,
        deleted_at: IsNull(),
      },
    });

    const docByTypeId = new Map(documents.map((d) => [d.document_type_id, d]));

    return docTypes.map((dt) => {
      const d = docByTypeId.get(dt.id) ?? null;
      return {
        document_type: {
          id: dt.id,
          code: dt.code,
          name: dt.name,
          has_expiration: dt.has_expiration,
          category: dt.category,
          sort_order: dt.sort_order,
        },
        document: d
          ? {
              id: d.id,
              file_name: d.file_name,
              file_path: d.file_path,
              file_size_bytes: d.file_size_bytes,
              mime_type: d.mime_type,
              extraction_status: d.extraction_status,
              created_at: d.created_at,
            }
          : null,
      };
    });
  }

  async getDocumentTypesByEmployeeTags(
    organizationId: string,
    employeeId: string,
    userId: string,
  ): Promise<RequiredDocumentItem[]> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const employeeTags = await this.employeeRequirementTagRepository.find({
      where: { employee_id: employeeId },
      select: ['requirement_tag_id'],
    });
    const tagIds = employeeTags.map((t) => t.requirement_tag_id);
    if (tagIds.length === 0) return [];

    const links = await this.requirementDocumentTypeRepository.find({
      where: { requirement_tag_id: In(tagIds) },
      select: ['document_type_id'],
    });
    const docTypeIds = [...new Set(links.map((l) => l.document_type_id))];
    if (docTypeIds.length === 0) return [];

    const docTypes = await this.hrDocumentTypeRepository.find({
      where: {
        id: In(docTypeIds),
        organization_id: organizationId,
        is_active: true,
      },
      order: { sort_order: 'ASC', id: 'ASC' },
    });

    const documents = await this.employeeDocumentRepository.find({
      where: {
        employee_id: employeeId,
        organization_id: organizationId,
        deleted_at: IsNull(),
      },
    });
    const docByTypeId = new Map(documents.map((d) => [d.document_type_id, d]));

    return docTypes.map((dt) => {
      const d = docByTypeId.get(dt.id) ?? null;
      return {
        document_type: {
          id: dt.id,
          code: dt.code,
          name: dt.name,
          has_expiration: dt.has_expiration,
          category: dt.category,
          sort_order: dt.sort_order,
        },
        document: d
          ? {
              id: d.id,
              file_name: d.file_name,
              file_path: d.file_path,
              file_size_bytes: d.file_size_bytes,
              mime_type: d.mime_type,
              extraction_status: d.extraction_status,
              created_at: d.created_at,
            }
          : null,
      };
    });
  }

  async getInserviceTrainingsByEmployeeTags(
    organizationId: string,
    employeeId: string,
    userId: string,
  ): Promise<
    Array<{
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
      status: 'not_started' | 'in_progress' | 'completed' | 'expired';
      progress_percent: number;
      completed_at: string | null;
      expiration_at: string | null;
      last_quiz_score_percent: number | null;
      quiz_attempts_count: number;
      created_at: Date;
      updated_at: Date;
    }>
  > {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const employeeTags = await this.employeeRequirementTagRepository.find({
      where: { employee_id: employeeId },
      select: ['requirement_tag_id'],
    });
    const tagIds = employeeTags.map((t) => t.requirement_tag_id);
    if (tagIds.length === 0) return [];

    const links = await this.requirementInserviceTrainingRepository.find({
      where: { requirement_tag_id: In(tagIds) },
      select: ['inservice_training_id'],
    });
    const inserviceIds = [...new Set(links.map((l) => l.inservice_training_id))];
    if (inserviceIds.length === 0) return [];

    const inservices = await this.inserviceTrainingRepository.find({
      where: {
        id: In(inserviceIds),
        organization_id: organizationId,
        is_active: true,
      },
      order: { sort_order: 'ASC', created_at: 'DESC' },
    });

    const completionMap =
      await this.inserviceCompletionService.getCompletionMap(
        employeeId,
        inservices.map((it) => it.id),
      );

    return inservices.map((it) => {
      const entry = completionMap.get(it.id)!;
      const status = this.inserviceCompletionService.getStatus(
        entry,
        it.has_quiz,
      );
      return {
        id: it.id,
        organization_id: it.organization_id,
        code: it.code,
        title: it.title,
        description: it.description,
        completion_frequency: it.completion_frequency,
        expiry_months: it.expiry_months,
        pdf_file_name: it.pdf_file_name,
        pdf_file_path: it.pdf_file_path,
        pdf_file_size_bytes: it.pdf_file_size_bytes
          ? Number(it.pdf_file_size_bytes)
          : null,
        video_url: it.video_url,
        sort_order: it.sort_order,
        is_active: it.is_active,
        has_quiz: it.has_quiz,
        passing_score_percent: it.passing_score_percent,
        status,
        progress_percent: entry.progress_percent,
        completed_at: entry.completed_at
          ? entry.completed_at.toISOString()
          : null,
        expiration_at: entry.expiration_at
          ? entry.expiration_at.toISOString()
          : null,
        last_quiz_score_percent: entry.last_quiz_score_percent,
        quiz_attempts_count: entry.quiz_attempts_count,
        created_at: it.created_at,
        updated_at: it.updated_at,
      };
    });
  }

  async getExpirationStatus(
    organizationId: string,
    employeeId: string,
    documentIds: string[],
    userId: string,
  ): Promise<ExpirationStatusItem[]> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const validIds = filterValidUuids(documentIds);
    if (!validIds?.length) {
      return [];
    }

    const docs = await this.employeeDocumentRepository.find({
      where: {
        id: In(validIds),
        organization_id: organizationId,
        employee_id: employeeId,
        deleted_at: IsNull(),
      },
      relations: ['documentType'],
    });

    const result: ExpirationStatusItem[] = [];

    for (const doc of docs) {
      const text = await this.getDocumentContentForExpiration(doc.id);
      const expirationDate = text ? await this.extractExpirationFromContent(text) : null;
      const expirationDateStr =
        expirationDate != null ? expirationDate.toISOString().slice(0, 10) : null;
      const is_expired = expirationDate != null ? expirationDate < new Date() : false;
      const status = getExpirationStatusType(expirationDate);

      result.push({
        document_id: doc.id,
        is_expired,
        expiration_date: expirationDateStr,
        document_type_name: doc.documentType?.name ?? 'Unknown',
        status,
      });
    }

    const foundIds = new Set(docs.map((d) => d.id));
    for (const id of validIds) {
      if (!foundIds.has(id)) {
        result.push({
          document_id: id,
          is_expired: false,
          expiration_date: null,
          document_type_name: 'Unknown',
          status: 'has_no_expiration_date',
        });
      }
    }

    return result;
  }

  private async getDocumentContentForExpiration(documentId: string): Promise<string | null> {
    const chunks = await this.documentChunkRepository.find({
      where: { document_id: documentId },
      order: { chunk_index: 'ASC' },
    });
    if (chunks.length > 0) {
      return chunks.map((c) => c.chunk_text).join('\n');
    }
    const doc = await this.employeeDocumentRepository.findOne({
      where: { id: documentId, deleted_at: IsNull() },
    });
    return doc?.extracted_text ?? null;
  }

  extractExpirationFromContent(text: string): Promise<Date | null> {
    if (!text?.trim()) return Promise.resolve(null);
    const matches = [...text.matchAll(EXPIRATION_DATE_REGEX)];
    for (const m of matches) {
      const dateStr = m[1];
      const parsed = this.parseDate(dateStr);
      if (parsed) return Promise.resolve(parsed);
    }
    return Promise.resolve(null);
  }

  private parseDate(str: string): Date | null {
    const normalized = str.replace(/-/g, '/').trim();

    const isoParts = normalized.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})$/);
    if (isoParts) {
      const y = parseInt(isoParts[1], 10);
      const m = parseInt(isoParts[2], 10);
      const d = parseInt(isoParts[3], 10);
      const date = new Date(y, m - 1, d);
      return isNaN(date.getTime()) ? null : date;
    }

    const parts = normalized.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);
    if (parts) {
      const p1 = parseInt(parts[1], 10);
      const p2 = parseInt(parts[2], 10);
      const y = parseInt(parts[3], 10);
      const year = y < 100 ? 2000 + y : y;
      let date: Date;
      if (p1 > 12) {
        date = new Date(year, p2 - 1, p1);
      } else if (p2 > 12) {
        date = new Date(year, p1 - 1, p2);
      } else {
        date = new Date(year, p2 - 1, p1);
      }
      return isNaN(date.getTime()) ? null : date;
    }

    return isNaN(new Date(normalized).getTime()) ? null : new Date(normalized);
  }

  async chatOrSummarize(
    organizationId: string,
    employeeId: string,
    message: string,
    documentIds: string[] | undefined,
    userId: string,
  ): Promise<{ answer: string; sources: ChatSource[] }> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const where: FindOptionsWhere<EmployeeDocument> = {
      organization_id: organizationId,
      employee_id: employeeId,
      deleted_at: IsNull(),
    };
    const validDocIds = filterValidUuids(documentIds);
    if (validDocIds?.length) {
      where.id = In(validDocIds);
    }

    const docs = await this.employeeDocumentRepository.find({
      where,
    });
    if (docs.length === 0) {
      return {
        answer: 'No documents found for this employee to search.',
        sources: [],
      };
    }

    const queryEmbedding = await this.embeddingService.embed(message.trim());
    if (!queryEmbedding?.length) {
      return {
        answer: 'Unable to search document content at this time. Please try again.',
        sources: [],
      };
    }

    const vectorStr = `[${queryEmbedding.join(',')}]`;
    const docIds = docs.map((d) => d.id);
    const chunkRows = await this.dataSource.query<
      Array<{ id: string; document_id: string; chunk_text: string }>
    >(
      `SELECT id, document_id, chunk_text
       FROM document_chunks
       WHERE organization_id = $1 AND employee_id = $2
         AND document_id = ANY($3::uuid[])
         AND embedding IS NOT NULL
       ORDER BY embedding <=> $4::vector
       LIMIT $5`,
      [organizationId, employeeId, docIds, vectorStr, VECTOR_SEARCH_LIMIT],
    );

    if (chunkRows.length === 0) {
      return {
        answer: 'No relevant content found in the documents for this question.',
        sources: [],
      };
    }

    const context = chunkRows.map((r) => r.chunk_text).join('\n\n');
    const docMap = new Map(docs.map((d) => [d.id, d]));

    let answer: string;
    if (this.openai) {
      const response = await this.openai.chat.completions.create({
        model: this.configService.get<string>('llm.model') ?? 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content: `Answer only from the provided context. If the context does not contain the answer, say so. Be concise.`,
          },
          { role: 'user', content: `Context:\n${context}\n\nQuestion: ${message}` },
        ],
      });
      answer = response.choices?.[0]?.message?.content?.trim() ?? 'No answer could be generated.';
    } else {
      answer = 'LLM is not configured; cannot generate an answer.';
    }

    const sources: ChatSource[] = chunkRows.map((r) => {
      const doc = docMap.get(r.document_id);
      return {
        document_id: r.document_id,
        file_name: doc?.file_name ?? 'Unknown',
        snippet: r.chunk_text.slice(0, 200) + (r.chunk_text.length > 200 ? '...' : ''),
      };
    });

    return { answer, sources };
  }

  async findOne(
    organizationId: string,
    employeeId: string,
    documentId: string,
    userId: string,
  ): Promise<EmployeeDocument> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);
    const doc = await this.employeeDocumentRepository.findOne({
      where: {
        id: documentId,
        organization_id: organizationId,
        employee_id: employeeId,
        deleted_at: IsNull(),
      },
      relations: ['documentType'],
    });
    if (!doc) {
      throw new NotFoundException('Document not found');
    }
    return doc;
  }

  async getFileForDownload(
    organizationId: string,
    employeeId: string,
    documentId: string,
    userId: string,
  ): Promise<{ stream: NodeJS.ReadableStream; contentType: string; file_name: string }> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);
    const doc = await this.employeeDocumentRepository.findOne({
      where: {
        id: documentId,
        organization_id: organizationId,
        employee_id: employeeId,
        deleted_at: IsNull(),
      },
    });
    if (!doc) {
      throw new NotFoundException('Document not found');
    }
    try {
      const { stream, contentType } = await this.storageService.getFileStream(
        doc.file_path,
        doc.file_name,
      );
      return { stream, contentType, file_name: doc.file_name };
    } catch {
      throw new NotFoundException('File not found in storage');
    }
  }

  async delete(
    organizationId: string,
    employeeId: string,
    documentId: string,
    userId: string,
  ): Promise<void> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);
    const doc = await this.employeeDocumentRepository.findOne({
      where: {
        id: documentId,
        organization_id: organizationId,
        employee_id: employeeId,
        deleted_at: IsNull(),
      },
    });
    if (!doc) {
      throw new NotFoundException('Document not found');
    }
    doc.deleted_at = new Date();
    await this.employeeDocumentRepository.save(doc);
  }

  async update(
    organizationId: string,
    employeeId: string,
    documentId: string,
    dto: UpdateEmployeeDocumentDto,
    userId: string,
  ): Promise<EmployeeDocument> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const doc = await this.employeeDocumentRepository.findOne({
      where: {
        id: documentId,
        organization_id: organizationId,
        employee_id: employeeId,
        deleted_at: IsNull(),
      },
    });
    if (!doc) {
      throw new NotFoundException('Document not found');
    }

    if (dto.file_name !== undefined) {
      doc.file_name = dto.file_name;
    }
    return this.employeeDocumentRepository.save(doc);
  }

  async upload(
    organizationId: string,
    employeeId: string,
    documentTypeId: string,
    file: { buffer: Buffer; originalFilename: string; mimeType?: string },
    userId: string,
  ): Promise<EmployeeDocument> {
    await this.ensureDocumentAccess(organizationId, employeeId, userId);

    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId },
    });
    if (!employee) {
      throw new NotFoundException('Employee not found');
    }

    const docType = await this.hrDocumentTypeRepository.findOne({
      where: [
        {
          id: documentTypeId,
          organization_id: organizationId,
          is_active: true,
          employee_id: IsNull(),
        },
        {
          id: documentTypeId,
          organization_id: IsNull(),
          is_active: true,
          employee_id: employeeId,
        },
      ],
    });
    if (!docType) {
      throw new NotFoundException('Document type not found');
    }

    const existing = await this.employeeDocumentRepository.findOne({
      where: {
        employee_id: employeeId,
        document_type_id: documentTypeId,
        deleted_at: IsNull(),
      },
    });
    if (existing) {
      throw new ConflictException(
        'A document of this type already exists for this employee. Delete it first to replace.',
      );
    }

    const { file_name, file_path } = await this.storageService.saveEmployeeDocument(
      file.buffer,
      file.originalFilename,
      organizationId,
      employeeId,
    );

    const doc = this.employeeDocumentRepository.create({
      organization_id: organizationId,
      employee_id: employeeId,
      document_type_id: documentTypeId,
      file_name,
      file_path,
      file_size_bytes: file.buffer.length,
      mime_type: file.mimeType ?? null,
      uploaded_by: userId,
      extraction_status: 'pending',
    });
    const saved = await this.employeeDocumentRepository.save(doc);

    this.runExtractionAndChunking(saved.id).catch((err) => {
      this.logger.warn(`Extraction failed for document ${saved.id}`, err);
    });

    return saved;
  }

  private async runExtractionAndChunking(documentId: string): Promise<void> {
    const doc = await this.employeeDocumentRepository.findOne({
      where: { id: documentId, deleted_at: IsNull() },
    });
    if (!doc) return;

    try {
      const { stream } = await this.storageService.getFileStream(doc.file_path, doc.file_name);
      const buffer = await streamToBuffer(stream);

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
          await this.employeeDocumentRepository.save(doc);
          return;
        }
      }

      doc.extracted_text = extractedText || null;
      doc.extraction_status = extractedText ? 'completed' : 'completed';
      doc.extraction_error = null;
      await this.employeeDocumentRepository.save(doc);

      await this.documentChunkRepository.delete({ document_id: documentId });

      if (!extractedText) return;

      const chunkSize = 1000;
      const overlap = 200;
      const chunks: string[] = [];
      for (let i = 0; i < extractedText.length; i += chunkSize - overlap) {
        const slice = extractedText.slice(i, i + chunkSize);
        if (slice.trim()) chunks.push(slice.trim());
      }

      for (let i = 0; i < chunks.length; i++) {
        const text = chunks[i].slice(0, MAX_EMBEDDING_TEXT_LENGTH);
        const embedding = await this.embeddingService.embed(text);
        if (!embedding?.length) continue;

        const vectorStr = `[${embedding.join(',')}]`;
        await this.dataSource.query(
          `INSERT INTO document_chunks (id, document_id, organization_id, employee_id, chunk_index, chunk_text, chunk_tokens, metadata, embedding)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, NULL, '{}', $6::vector)`,
          [documentId, doc.organization_id, doc.employee_id, i, chunks[i], vectorStr],
        );
      }
    } catch (err) {
      doc.extraction_error = err instanceof Error ? err.message : String(err);
      doc.extraction_status = 'failed';
      await this.employeeDocumentRepository.save(doc);
    }
  }
}
