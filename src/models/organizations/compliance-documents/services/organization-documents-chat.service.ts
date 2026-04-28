import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, In, IsNull, Repository } from 'typeorm';
import { OrganizationDocument } from '../entities/organization-document.entity';
import { OrganizationDocumentsService } from './organization-documents.service';
import { EmbeddingService } from '../../../../common/services/embedding/embedding.service';
import { LlmRouter, type LlmMessage, type LlmTool } from '../../../../common/services/llm';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VECTOR_SEARCH_LIMIT = 10;
const MAX_ITERATIONS = 10;

function filterValidUuids(ids: unknown): string[] {
  if (!Array.isArray(ids)) return [];
  return (ids as string[]).filter((id) => typeof id === 'string' && UUID_REGEX.test(id));
}

export interface ComplianceChatSource {
  document_id: string;
  document_name: string;
  file_name: string;
  snippet: string;
}

const GENERAL_SYSTEM_PROMPT = `You are a compliance document assistant for a healthcare organization. The organization's documents are already uploaded in the system.

You have tools to access all compliance documents, check their status, search content, analyze documents, and compare them. For ANY question about documents, you MUST use the appropriate tool and answer only from tool results.

Available capabilities:
- List and filter documents by category or status
- Get compliance dashboard stats (total, valid, expired, expiring soon, missing)
- Search document content semantically
- Get full details of a specific document
- Get expiration alerts sorted by urgency
- Analyze a document (extract dates, key terms, summary, compliance check)
- Compare multiple documents side by side

Do NOT ask the user to upload documents. Do NOT make up information—only answer from tool results. If a tool returns no results, say so briefly.`;

function buildSingleDocumentSystemPrompt(
  docNames: { id: string; name: string; category: string }[],
): string {
  const docList = docNames
    .map((d) => `- "${d.name}" (category: ${d.category}, ID: ${d.id})`)
    .join('\n');
  return `You are a compliance document assistant. The user is asking about specific document(s) that are already in the system:

${docList}

You have tools to get document details, search content, and analyze the document. For ANY question, you MUST call the appropriate tool using the document ID(s) above. NEVER ask the user which document—you already know.

When calling get_compliance_document_details or analyze_compliance_document, use the document ID above. When calling search_compliance_documents, the search is already scoped to this document.

Do NOT make up information—only answer from tool results. If a tool returns no results, say so briefly.`;
}

const SINGLE_DOCUMENT_TOOLS: LlmTool[] = [
  {
    name: 'get_compliance_document_details',
    description:
      'Get full details of the document including extracted text, status, and expiration info. Call this first to answer questions about the document.',
    parameters: {
      type: 'object',
      properties: {
        document_id: {
          type: 'string',
          format: 'uuid',
          description: 'UUID of the document (use the one from context)',
        },
      },
      required: ['document_id'],
    },
  },
  {
    name: 'search_compliance_documents',
    description:
      'Search the document content semantically. Use for specific questions about what the document contains.',
    parameters: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Natural language search query',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'analyze_compliance_document',
    description:
      'AI analysis: extract dates, key terms, parties, obligations, summary, or compliance check.',
    parameters: {
      type: 'object',
      properties: {
        document_id: {
          type: 'string',
          format: 'uuid',
          description: 'UUID of the document (use the one from context)',
        },
        analysis_type: {
          type: 'string',
          enum: ['full', 'expiration', 'key_terms', 'summary', 'compliance_check'],
          description: 'Type of analysis (default: full)',
        },
      },
      required: ['document_id'],
    },
  },
];

const TOOLS: LlmTool[] = [
  {
    name: 'list_compliance_documents',
    description:
      'List compliance documents, optionally filtered by category or status. Use when asked to show, list, or find documents.',
    parameters: {
      type: 'object',
      properties: {
        category_id: {
          type: 'string',
          description: 'Filter by category UUID',
        },
        status: {
          type: 'string',
          enum: ['valid', 'expired', 'expiring_soon', 'missing'],
          description: 'Filter by status',
        },
        limit: {
          type: 'number',
          description: 'Max results (default 50)',
        },
      },
    },
  },
  {
    name: 'get_compliance_stats',
    description:
      'Get compliance stats: total, valid, expiring soon, expired, missing counts with per-category breakdown. Use for overview questions.',
    parameters: { type: 'object', properties: {} },
  },
  {
    name: 'get_compliance_document_details',
    description:
      'Get full details of a specific document including extracted text content, status, and expiration info.',
    parameters: {
      type: 'object',
      properties: {
        document_id: {
          type: 'string',
          format: 'uuid',
          description: 'UUID of the document',
        },
      },
      required: ['document_id'],
    },
  },
  {
    name: 'search_compliance_documents',
    description:
      'Semantic search across document content. Finds relevant passages even without exact keyword matches. Use for any question about what documents contain.',
    parameters: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Natural language search query',
        },
        category_id: {
          type: 'string',
          description: 'Optional: restrict to a category',
        },
        limit: {
          type: 'number',
          description: 'Max results (default 10)',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'get_expiring_documents_alert',
    description:
      'Get prioritized alerts: expired, expiring soon, and missing documents sorted by urgency. Use when asked what needs attention.',
    parameters: {
      type: 'object',
      properties: {
        days_ahead: {
          type: 'number',
          description: 'Look-ahead window in days (default 90)',
        },
      },
    },
  },
  {
    name: 'analyze_compliance_document',
    description:
      'AI analysis of a document: extract dates, key terms, parties, obligations, or check compliance. Use when asked to analyze, scan, or review a document.',
    parameters: {
      type: 'object',
      properties: {
        document_id: {
          type: 'string',
          format: 'uuid',
          description: 'UUID of the document to analyze',
        },
        analysis_type: {
          type: 'string',
          enum: ['full', 'expiration', 'key_terms', 'summary', 'compliance_check'],
          description: 'Type of analysis (default: full)',
        },
      },
      required: ['document_id'],
    },
  },
  {
    name: 'compare_compliance_documents',
    description:
      'Compare 2-5 documents side by side. Use when asked to compare policies, find differences, or check which document is better.',
    parameters: {
      type: 'object',
      properties: {
        document_ids: {
          type: 'array',
          items: { type: 'string', format: 'uuid' },
          minItems: 2,
          maxItems: 5,
          description: 'Document UUIDs to compare',
        },
        comparison_focus: {
          type: 'string',
          description: 'Optional aspect to focus on',
        },
      },
      required: ['document_ids'],
    },
  },
];

@Injectable()
export class OrganizationDocumentsChatService {
  private readonly logger = new Logger(OrganizationDocumentsChatService.name);

  constructor(
    @InjectRepository(OrganizationDocument)
    private readonly documentRepository: Repository<OrganizationDocument>,
    private readonly documentsService: OrganizationDocumentsService,
    private readonly embeddingService: EmbeddingService,
    private readonly configService: ConfigService,
    private readonly dataSource: DataSource,
    private readonly llm: LlmRouter,
  ) {}

  async chat(
    organizationId: string,
    message: string,
    history?: { role: 'user' | 'assistant'; content: string }[],
    documentIds?: string[],
  ): Promise<{
    message: string;
    sources?: ComplianceChatSource[];
  }> {
    let systemPrompt = GENERAL_SYSTEM_PROMPT;
    let activeTools = TOOLS;

    if (documentIds?.length) {
      const docs = await this.documentRepository.find({
        where: { id: In(documentIds), organization_id: organizationId, deleted_at: IsNull() },
        relations: ['category'],
      });
      if (docs.length > 0) {
        systemPrompt = buildSingleDocumentSystemPrompt(
          docs.map((d) => ({
            id: d.id,
            name: d.document_name,
            category: d.category?.name ?? 'Unknown',
          })),
        );
        activeTools = SINGLE_DOCUMENT_TOOLS;
      }
    }

    const messages: LlmMessage[] = [
      { role: 'system', content: systemPrompt },
      ...(history ?? []).map<LlmMessage>((h) =>
        h.role === 'assistant'
          ? { role: 'assistant', content: h.content }
          : { role: 'user', content: h.content },
      ),
      { role: 'user', content: message },
    ];

    const model = this.configService.get<string>('llm.model') ?? 'gpt-4o-mini';
    const providerName = await this.llm.resolveName(organizationId);
    let lastSources: ComplianceChatSource[] | undefined;
    let iteration = 0;

    while (iteration < MAX_ITERATIONS) {
      const response = await this.llm.generate(
        {
          messages,
          tools: activeTools,
          toolChoice: 'auto',
          model: providerName === 'openai' ? model : undefined,
        },
        { organizationId },
      );

      const assistantMessage = response.message;
      messages.push(assistantMessage);

      if (!assistantMessage.toolCalls?.length) {
        return { message: assistantMessage.content ?? '', sources: lastSources };
      }

      for (const tc of assistantMessage.toolCalls) {
        let args: Record<string, unknown> = {};
        try {
          args = (tc.arguments ? JSON.parse(tc.arguments) : {}) as Record<string, unknown>;
        } catch {
          this.logger.warn(`Invalid tool arguments for ${tc.name}`);
        }

        const result = await this.runTool(organizationId, tc.name, args, documentIds);

        let content: string;
        if (typeof result === 'object' && result && 'text' in result) {
          content = (result as { text: string }).text;
          if ('sources' in result) lastSources = (result as { sources: ComplianceChatSource[] }).sources;
        } else {
          content = typeof result === 'string' ? result : JSON.stringify(result);
        }

        messages.push({ role: 'tool', toolCallId: tc.id, content });
      }

      iteration++;
    }

    return {
      message: 'I hit a limit on tool use. Please ask again in a shorter way.',
      sources: lastSources,
    };
  }

  async analyzeDocument(
    organizationId: string,
    documentId: string,
    analysisType: string = 'full',
  ): Promise<Record<string, unknown>> {
    const doc = await this.documentRepository.findOne({
      where: { id: documentId, organization_id: organizationId, deleted_at: IsNull() },
      relations: ['category'],
    });
    if (!doc) return { error: 'Document not found' };
    if (!doc.extracted_text) return { error: 'Document has not been scanned yet' };

    const promptMap: Record<string, string> = {
      full: 'Analyze this document thoroughly. Extract: summary, key dates (effective, expiration, renewal deadlines), key parties, key terms/obligations, and any compliance concerns.',
      expiration: 'Extract all dates from this document: effective dates, expiration dates, renewal deadlines, and any other important dates.',
      key_terms: 'Extract all key terms, obligations, coverage details, limits, and conditions from this document.',
      summary: 'Provide a brief 2-3 sentence summary of this document.',
      compliance_check: 'Review this document for compliance issues: expired dates, missing required information, coverage gaps, or any red flags.',
    };

    const systemPrompt = promptMap[analysisType] ?? promptMap.full;
    const truncatedText = doc.extracted_text.slice(0, 12000);
    const model = this.configService.get<string>('llm.model') ?? 'gpt-4o-mini';
    const providerName = await this.llm.resolveName(organizationId);

    const response = await this.llm.generate(
      {
        messages: [
          { role: 'system', content: `${systemPrompt} Respond in structured JSON format.` },
          { role: 'user', content: truncatedText },
        ],
        responseFormat: 'json_object',
        model: providerName === 'openai' ? model : undefined,
      },
      { organizationId },
    );

    const content = response.message.content?.trim() ?? '{}';
    let analysis: Record<string, unknown>;
    try {
      analysis = JSON.parse(content);
    } catch {
      analysis = { raw_analysis: content };
    }

    return {
      document_id: doc.id,
      document_name: doc.document_name,
      category: doc.category?.name ?? 'Unknown',
      analysis,
    };
  }

  async compareDocuments(
    organizationId: string,
    documentIds: string[],
    comparisonFocus?: string,
  ): Promise<Record<string, unknown>> {
    const docs = await this.documentRepository.find({
      where: { id: In(documentIds), organization_id: organizationId, deleted_at: IsNull() },
      relations: ['category'],
    });

    if (docs.length < 2) return { error: 'Need at least 2 valid documents to compare' };

    const docsContext = docs
      .map((d, i) => {
        const text = (d.extracted_text ?? '').slice(0, 6000);
        return `--- Document ${i + 1}: ${d.document_name} (${d.category?.name ?? 'Unknown'}) ---\n${text}`;
      })
      .join('\n\n');

    const focusInstruction = comparisonFocus
      ? `Focus the comparison on: ${comparisonFocus}.`
      : 'Compare all relevant aspects.';

    const model = this.configService.get<string>('llm.model') ?? 'gpt-4o-mini';
    const providerName = await this.llm.resolveName(organizationId);
    const response = await this.llm.generate(
      {
        messages: [
          {
            role: 'system',
            content: `Compare the following compliance documents. ${focusInstruction} Provide a structured comparison with differences, similarities, and a summary. Respond in JSON format.`,
          },
          { role: 'user', content: docsContext },
        ],
        responseFormat: 'json_object',
        model: providerName === 'openai' ? model : undefined,
      },
      { organizationId },
    );

    const content = response.message.content?.trim() ?? '{}';
    let comparison: Record<string, unknown>;
    try {
      comparison = JSON.parse(content);
    } catch {
      comparison = { raw_comparison: content };
    }

    return {
      documents: docs.map((d) => ({ id: d.id, name: d.document_name, category: d.category?.name })),
      comparison,
    };
  }

  private async runTool(
    organizationId: string,
    name: string,
    args: Record<string, unknown>,
    contextDocumentIds?: string[],
  ): Promise<string | { text: string; sources?: ComplianceChatSource[] }> {
    try {
      switch (name) {
        case 'list_compliance_documents': {
          const result = await this.documentsService.findAll(organizationId, {
            category_id: typeof args.category_id === 'string' ? args.category_id : undefined,
            status: typeof args.status === 'string' ? args.status : undefined,
            limit: typeof args.limit === 'number' ? args.limit : 50,
            page: 1,
          });
          return JSON.stringify(result.data, null, 2);
        }

        case 'get_compliance_stats': {
          const result = await this.documentsService.getStats(organizationId);
          return JSON.stringify(result, null, 2);
        }

        case 'get_compliance_document_details': {
          const docId =
            (typeof args.document_id === 'string' ? args.document_id : '') ||
            contextDocumentIds?.[0] ||
            '';
          const result = await this.documentsService.getDocumentDetails(organizationId, docId);
          return JSON.stringify(result, null, 2);
        }

        case 'search_compliance_documents': {
          const query = typeof args.query === 'string' ? args.query : '';
          const catId = typeof args.category_id === 'string' ? args.category_id : undefined;
          const limit = typeof args.limit === 'number' ? args.limit : 10;
          const result = await this.documentsService.semanticSearch(
            organizationId,
            query,
            catId,
            limit,
            contextDocumentIds,
          );

          const sources: ComplianceChatSource[] = result.results.map((r) => ({
            document_id: r.document_id,
            document_name: r.document_name,
            file_name: '',
            snippet: r.snippet,
          }));

          return {
            text: JSON.stringify(result, null, 2),
            sources,
          };
        }

        case 'get_expiring_documents_alert': {
          const daysAhead = typeof args.days_ahead === 'number' ? args.days_ahead : 90;
          const result = await this.documentsService.getExpiringDocuments(organizationId, daysAhead);
          return JSON.stringify(result, null, 2);
        }

        case 'analyze_compliance_document': {
          const docId =
            (typeof args.document_id === 'string' ? args.document_id : '') ||
            contextDocumentIds?.[0] ||
            '';
          const analysisType = typeof args.analysis_type === 'string' ? args.analysis_type : 'full';
          const result = await this.analyzeDocument(organizationId, docId, analysisType);
          return JSON.stringify(result, null, 2);
        }

        case 'compare_compliance_documents': {
          const docIds = filterValidUuids(args.document_ids);
          const focus = typeof args.comparison_focus === 'string' ? args.comparison_focus : undefined;
          if (docIds.length < 2) return 'Need at least 2 valid document IDs to compare.';
          const result = await this.compareDocuments(organizationId, docIds, focus);
          return JSON.stringify(result, null, 2);
        }

        default:
          return `Unknown tool: ${name}`;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Tool ${name} failed: ${msg}`);
      return `Error: ${msg}`;
    }
  }
}
