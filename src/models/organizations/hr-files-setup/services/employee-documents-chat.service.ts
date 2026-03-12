import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import OpenAI from 'openai';
import { EmployeeDocumentsService } from './employee-documents.service';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function filterValidDocumentIds(ids: unknown): string[] {
  if (!Array.isArray(ids)) return [];
  return (ids as string[]).filter((id) => typeof id === 'string' && UUID_REGEX.test(id));
}

const SYSTEM_PROMPT = `You are a helpful assistant for an employee who has already uploaded HR documents. The documents are already in the system—do NOT ask the user to upload or provide a document.

You have full access to the document content via the chat_with_employee_document tool. For ANY question about the document—including its content, summary, expiration date, dates, or any other detail—you MUST call chat_with_employee_document with the user's message and answer only from the tool result. Do not ask for document IDs; the backend uses the current document in context.

If the tool returns "No relevant content found", say so briefly. Answer only from tool results. If the question is unrelated to HR documents, say you can only help with document-related questions.`;

const TOOLS: OpenAI.Chat.Completions.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
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
  },
  {
    type: 'function',
    function: {
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
  },
];

@Injectable()
export class EmployeeDocumentsChatService {
  private readonly logger = new Logger(EmployeeDocumentsChatService.name);
  private readonly openai: OpenAI | null = null;

  constructor(
    private readonly configService: ConfigService,
    private readonly employeeDocumentsService: EmployeeDocumentsService,
  ) {
    const apiKey = this.configService.get<string>('apiKeys.openai')?.trim();
    if (apiKey) {
      this.openai = new OpenAI({ apiKey });
    }
  }

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
    if (!this.openai) {
      return {
        message: 'Chat is not available. Please set OPENAI_API_KEY.',
      };
    }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      ...(history ?? []).map(
        (h) =>
          ({
            role: h.role,
            content: h.content,
          }) as OpenAI.Chat.Completions.ChatCompletionMessageParam,
      ),
      { role: 'user', content: message },
    ];

    const model = this.configService.get<string>('llm.model') ?? 'gpt-4o-mini';
    let lastSources: { document_id: string; file_name: string; snippet: string }[] | undefined;
    let iteration = 0;
    const maxIterations = 10;

    while (iteration < maxIterations) {
      const response = await this.openai.chat.completions.create({
        model,
        messages,
        tools: TOOLS,
        tool_choice: 'auto',
      });

      const choice = response.choices?.[0];
      if (!choice?.message) {
        return { message: 'I could not generate a response. Please try again.' };
      }

      const assistantMessage = choice.message;
      messages.push(assistantMessage);

      if (!assistantMessage.tool_calls?.length) {
        const raw = assistantMessage.content;
        const reply =
          typeof raw === 'string'
            ? raw
            : Array.isArray(raw)
              ? (raw as Array<{ type?: string; text?: string } | string>)
                  .map((c) => (typeof c === 'string' ? c : (c?.text ?? '')))
                  .join('')
              : '';
        return { message: reply || '', sources: lastSources };
      }

      for (const tc of assistantMessage.tool_calls) {
        if (tc.type !== 'function' || tc.function?.name == null) continue;
        const name = tc.function.name;
        let args: Record<string, unknown> = {};
        try {
          args = (tc.function.arguments ? JSON.parse(tc.function.arguments) : {}) as Record<
            string,
            unknown
          >;
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
          tool_call_id: tc.id,
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
