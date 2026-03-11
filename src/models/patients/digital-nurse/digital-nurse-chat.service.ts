import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import OpenAI from 'openai';
import {
  MedicationsService,
  type MedicationAuditContext,
  type MedicationResponse,
} from '../medications/medications.service';

const SYSTEM_PROMPT = `You are a helpful digital nurse. Use the provided tools to list, search, or record the patient's medications. Answer briefly and in a friendly way. If the user asks something unrelated to medications, say you can only help with medication information and logging.`;

const TOOLS: OpenAI.Chat.Completions.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'list_medications',
      description:
        "List the patient's current medications with today's taken status. Use for 'what meds do I take', 'medication list', 'today's doses'.",
      parameters: {
        type: 'object',
        properties: {
          date: {
            type: 'string',
            description: 'Date in YYYY-MM-DD format. Defaults to today.',
          },
        },
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'search_medications',
      description:
        "Semantic search over the patient's medications. Use for finding medications by purpose, time, or condition (e.g. 'blood pressure', 'evening pills').",
      parameters: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search query (e.g. "blood pressure", "evening pills")',
          },
        },
        required: ['query'],
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'mark_medication_taken',
      description:
        "Record that the patient took a medication at a time slot on a given date. Use when the user says they took a dose or to log adherence. For medicationId use the UUID from list_medications/search_medications (the id: value in each line), or the medication name (e.g. 'Panando') and the backend will resolve it.",
      parameters: {
        type: 'object',
        properties: {
          medicationId: {
            type: 'string',
            description:
              'Medication UUID from list/search result (id: ...) or medication name (e.g. Panando)',
          },
          timeSlot: {
            type: 'string',
            description:
              'Time slot from the medication list (e.g. 08:00, 8:00, 20:00). Must be one of the times shown in parentheses for that medication.',
          },
          date: { type: 'string', description: 'Date in YYYY-MM-DD format' },
        },
        required: ['medicationId', 'timeSlot', 'date'],
      },
    },
  },
];

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizeTimeSlot(s: string): string {
  const trimmed = s.trim().toLowerCase();
  const match = trimmed.match(/^(\d{1,2}):(\d{2})\s*(am|pm)?$/);
  if (!match) return trimmed;
  let h = parseInt(match[1], 10);
  const m = match[2];
  const ampm = match[3];
  if (ampm === 'pm' && h < 12) h += 12;
  if (ampm === 'am' && h === 12) h = 0;
  return `${h.toString().padStart(2, '0')}:${m}`;
}

function resolveTimeSlot(requested: string, configuredSlots: string[]): string | null {
  const normalized = normalizeTimeSlot(requested);
  for (const slot of configuredSlots) {
    if (normalizeTimeSlot(slot) === normalized) return slot;
  }
  return null;
}

function formatMedicationList(list: MedicationResponse[]): string {
  if (!list.length) return 'No medications found.';
  return list
    .map((m) => {
      const parts = [`- id: ${m.id} | ${m.name}`];
      if (m.dosage) parts.push(` ${m.dosage}`);
      const times = m.timeSlots?.length ? m.timeSlots.join(', ') : 'no times';
      parts.push(` (${times})`);
      const todayStatus = (m.takenForDate ?? [])
        .map((t) => `${t.timeSlot}: ${t.taken ? 'taken' : 'not taken'}`)
        .join('; ');
      if (todayStatus) parts.push(` – today: ${todayStatus}`);
      return parts.join('');
    })
    .join('\n');
}

@Injectable()
export class DigitalNurseChatService {
  private readonly logger = new Logger(DigitalNurseChatService.name);
  private readonly openai: OpenAI | null = null;
  private readonly model: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly medicationsService: MedicationsService,
  ) {
    const apiKey = this.configService.get<string>('apiKeys.openai')?.trim();
    this.model = this.configService.get<string>('llm.model') ?? 'gpt-4o-mini';
    if (apiKey) {
      this.openai = new OpenAI({ apiKey });
    }
  }

  async chat(
    patientId: string,
    message: string,
    auditContext: MedicationAuditContext,
    history?: { role: 'user' | 'assistant'; content: string }[],
  ): Promise<{ reply: string }> {
    if (!this.openai) {
      return {
        reply: 'Chat is not available. Please set OPENAI_API_KEY.',
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

    let iteration = 0;
    const maxIterations = 10;

    while (iteration < maxIterations) {
      const response = await this.openai.chat.completions.create({
        model: this.model,
        messages,
        tools: TOOLS,
        tool_choice: 'auto',
      });

      const choice = response.choices?.[0];
      if (!choice?.message) {
        return { reply: 'I could not generate a response. Please try again.' };
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
        return { reply: reply || '' };
      }

      for (const tc of assistantMessage.tool_calls) {
        if (tc.type !== 'function' || tc.function?.name === undefined) continue;
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
        const result = await this.runTool(patientId, auditContext, name, args);
        messages.push({
          role: 'tool',
          tool_call_id: tc.id,
          content: result,
        });
      }
      iteration++;
    }

    return {
      reply: 'I hit a limit on tool use. Please ask again in a shorter way.',
    };
  }

  private async runTool(
    patientId: string,
    auditContext: MedicationAuditContext,
    name: string,
    args: Record<string, unknown>,
  ): Promise<string> {
    try {
      switch (name) {
        case 'list_medications': {
          const date =
            typeof args.date === 'string' ? args.date : new Date().toISOString().slice(0, 10);
          const list = await this.medicationsService.findAll(patientId, date, auditContext);
          return formatMedicationList(list);
        }
        case 'search_medications': {
          const query = typeof args.query === 'string' ? args.query.trim() : '';
          const list = await this.medicationsService.searchByQuery(patientId, query, auditContext);
          return formatMedicationList(list);
        }
        case 'mark_medication_taken': {
          const medicationIdOrName = (
            typeof args.medicationId === 'string' ? args.medicationId : ''
          ).trim();
          const requestedSlot = (typeof args.timeSlot === 'string' ? args.timeSlot : '').trim();
          const date = (typeof args.date === 'string' ? args.date : '').slice(0, 10);
          let resolvedId: string;
          let list: MedicationResponse[];
          if (UUID_REGEX.test(medicationIdOrName)) {
            resolvedId = medicationIdOrName;
            list = await this.medicationsService.findAll(patientId, date, auditContext);
          } else {
            list = await this.medicationsService.findAll(patientId, date, auditContext);
            const query = medicationIdOrName.toLowerCase();
            const byName = list.filter((m) => m.name.toLowerCase().includes(query));
            const exact = list.find((m) => m.name.toLowerCase() === query);
            const match = exact ?? byName[0];
            if (!match) {
              return `No medication found matching "${medicationIdOrName}". Use list_medications to see ids and names.`;
            }
            if (byName.length > 1 && !exact) {
              return `Multiple medications match "${medicationIdOrName}". Use the exact id from list_medications: ${byName.map((m) => m.id).join(', ')}`;
            }
            resolvedId = match.id;
          }
          const med = list.find((m) => m.id === resolvedId);
          if (!med) {
            return `Medication ${resolvedId} not found for this patient.`;
          }
          const resolvedSlot = resolveTimeSlot(requestedSlot, med.timeSlots ?? []);
          if (!resolvedSlot) {
            const valid = (med.timeSlots ?? []).length ? (med.timeSlots ?? []).join(', ') : 'none';
            return `Time slot "${requestedSlot}" is not configured for this medication. Valid slots: ${valid}. Use one of these exact values.`;
          }
          const result = await this.medicationsService.markAsTaken(
            patientId,
            resolvedId,
            { timeSlot: resolvedSlot, date },
            auditContext,
          );
          return `Recorded: ${result.timeSlot} on ${date} – taken.`;
        }
        default:
          return `Unknown tool: ${name}`;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Tool ${name} failed: ${message}`);
      return `Error: ${message}`;
    }
  }
}
