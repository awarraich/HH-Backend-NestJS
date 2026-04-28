import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EmployeeDocumentsService } from './employee-documents.service';
import { LlmRouter, type LlmMessage, type LlmTool } from '../../../../common/services/llm';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function filterValidDocumentIds(ids: unknown): string[] {
  if (!Array.isArray(ids)) return [];
  return (ids as string[]).filter((id) => typeof id === 'string' && UUID_REGEX.test(id));
}

const SYSTEM_PROMPT = `You are a helpful assistant for an employee who has already uploaded HR documents. The documents are already in the system—do NOT ask the user to upload or provide a document.

You have full access to the document content via the chat_with_employee_document tool. For ANY question about the document—including its content, summary, expiration date, dates, or any other detail—you MUST call chat_with_employee_document with the user's message and answer only from the tool result. Do not ask for document IDs; the backend uses the current document in context.

If the tool returns "No relevant content found", say so briefly. Answer only from tool results. If the question is unrelated to HR documents, say you can only help with document-related questions.`;

const TOOLS: LlmTool[] = [
  {
    name: 'get_document_expiration_status',
    description:
      "For a list of employee document IDs, returns whether each document is expired and its expiration date (derived from document content). Use when the user asks which documents are expired or about expiration status. Input: document_ids from the employee's required documents.",
    parameters: {
      type: 'object',
      properties: {
        document_ids: {
          type: 'array',
          items: { type: 'string', format: 'uuid' },
          description: 'Array of document UUIDs',
        },
      },
      required: ['document_ids'],
    },
  },
  {
    name: 'chat_with_employee_document',
    description:
      "Full access to the employee's document content. Use for ANY question about the document: content, summary, expiration date, dates, or other details. Pass the user's message; the backend uses the current document in context. Answer only from the tool result.",
    parameters: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          description:
            "The user's question or message (e.g. 'What is the expiration date?', 'Summarize this document')",
        },
        document_ids: {
          type: 'array',
          items: { type: 'string', format: 'uuid' },
          description: 'Optional: restrict to these document IDs',
        },
      },
      required: ['message'],
    },
  },
];

@Injectable()
export class EmployeeDocumentsChatService {
  private readonly logger = new Logger(EmployeeDocumentsChatService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly employeeDocumentsService: EmployeeDocumentsService,
    private readonly llm: LlmRouter,
  ) {}

  async chat(
    organizationId: string,
    employeeId: string,
    message: string,
    userId: string,
    history?: { role: 'user' | 'assistant'; content: string }[],
    documentId?: string,
  ): Promise<{
    message: string;
    sources?: { document_id: string; file_name: string; snippet: string }[];
  }> {
    const messages: LlmMessage[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...(history ?? []).map<LlmMessage>((h) =>
        h.role === 'assistant'
          ? { role: 'assistant', content: h.content }
          : { role: 'user', content: h.content },
      ),
      { role: 'user', content: message },
    ];

    const model = this.configService.get<string>('llm.model') ?? 'gpt-4o-mini';
    const providerName = await this.llm.resolveName(organizationId);
    let lastSources: { document_id: string; file_name: string; snippet: string }[] | undefined;
    let iteration = 0;
    const maxIterations = 10;

    while (iteration < maxIterations) {
      const response = await this.llm.generate(
        {
          messages,
          tools: TOOLS,
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
        const name = tc.name;
        let args: Record<string, unknown> = {};
        try {
          args = (tc.arguments ? JSON.parse(tc.arguments) : {}) as Record<string, unknown>;
        } catch {
          this.logger.warn(`Invalid tool arguments for ${name}`);
        }
        const result = await this.runTool(
          organizationId,
          employeeId,
          userId,
          name,
          args,
          name === 'chat_with_employee_document' ? documentId : undefined,
        );
        let content: string;
        if (typeof result === 'object' && result && 'text' in result) {
          content = result.text;
          if (result.sources) lastSources = result.sources;
        } else {
          content = typeof result === 'string' ? result : JSON.stringify(result);
        }
        messages.push({
          role: 'tool',
          toolCallId: tc.id,
          content,
        });
      }
      iteration++;
    }

    return {
      message: 'I hit a limit on tool use. Please ask again in a shorter way.',
      sources: lastSources,
    };
  }

  private async runTool(
    organizationId: string,
    employeeId: string,
    userId: string,
    name: string,
    args: Record<string, unknown>,
    requestDocumentId?: string,
  ): Promise<
    | string
    | { text: string; sources?: { document_id: string; file_name: string; snippet: string }[] }
  > {
    try {
      switch (name) {
        case 'get_document_expiration_status': {
          const documentIds = filterValidDocumentIds(args.document_ids);
          const list = await this.employeeDocumentsService.getExpirationStatus(
            organizationId,
            employeeId,
            documentIds,
            userId,
          );
          return JSON.stringify(list, null, 2);
        }
        case 'chat_with_employee_document': {
          const message = typeof args.message === 'string' ? args.message.trim() : '';
          let documentIds: string[] | undefined;
          if (requestDocumentId && UUID_REGEX.test(requestDocumentId)) {
            documentIds = [requestDocumentId];
          } else {
            const rawIds = Array.isArray(args.document_ids) ? args.document_ids : undefined;
            documentIds = rawIds?.length ? filterValidDocumentIds(rawIds) : undefined;
          }
          const result = await this.employeeDocumentsService.chatOrSummarize(
            organizationId,
            employeeId,
            message || 'Summarize these documents.',
            documentIds,
            userId,
          );
          return { text: result.answer, sources: result.sources };
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
