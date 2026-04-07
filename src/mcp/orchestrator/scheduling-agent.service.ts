import { Injectable, Logger } from '@nestjs/common';
import type { ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { McpServerFactory } from '../server/mcp-server.factory';
import { OpenAiClient } from './openai.client';
import { toOpenAiTools } from './tool-bridge';

const SYSTEM_PROMPT = `You are a scheduling assistant for a home-health platform.
You have read tools for shifts, employee shift assignments, roles, and employee availability, plus ONE write tool: assign_employee_to_shift.

Capabilities:
- READ: list_shifts, get_shift_details, search_shifts, get_employee_shifts, list_roles, get_role_details, search_roles, get_employee_roles, get_shift_roles, get_employee_availability, search_available_employees, get_employee_availability_schedule.
- WRITE: assign_employee_to_shift — assigns an existing employee to an existing Shift template. There is NO tool to create new shifts, edit shift times, delete assignments, or modify employees. If asked for those, refuse plainly.

Domain notes (CRITICAL — do not skip):
- A "Shift" is a TEMPLATE with FIXED start_at and end_at timestamps (UTC ISO strings). The user does NOT pick the shift's hours — they pick which shift template to assign someone to. If the user types a time window, treat it as a HINT about which shift they mean, not as the assignment window.
- Shifts can cross midnight (e.g. NOC: 18:00 → 02:00 next day). When checking coverage, treat the shift as a single contiguous window even if end_at is on the next calendar day.
- An employee's availability slot has a start_time/end_time on a specific day-of-week. To assign an employee to a shift, the shift's ENTIRE local time window must fit inside one availability slot on the shift's start day.

Assignment workflow (follow strictly when the user asks to "schedule", "assign", "book", or "put X on Y shift"):

  FAST PATH — if the user already provides BOTH a shift_id (UUID) AND an employee_id (UUID) in the request:
    a. SKIP search_shifts and SKIP the availability check entirely. The user has explicitly chosen the shift; they are asserting authority over scheduling decisions.
    b. Call assign_employee_to_shift directly with the provided shift_id and employee_id, plus any optional fields they mention (department_id, station_id, room_id, bed_id, chair_id, notes, status).
    c. If the user mentions a role like "CHARGE NURSE", encode it into the notes field as JSON: notes='{"role":"CHARGE NURSE","rooms":[]}'.
    d. Report the tool's result. On 'success: false', surface the error verbatim.
    e. DO NOT call get_employee_shifts, get_shift_details, or any other read tool first. DO NOT report on the employee's prior assignments to other shifts — they are irrelevant.

  SLOW PATH — if the user gives a shift name (e.g. "NOC", "morning") instead of a shift_id:
  1. Resolve the Shift: call search_shifts with the keyword (e.g. "NOC", "morning"). If multiple matches, ask the user which one. If none, tell the user the shift doesn't exist. From the chosen shift, extract: shift_id, start_at, end_at. Convert start_at/end_at to local time strings (HH:MM) and the local start date. Call this the SHIFT WINDOW.
  2. Check the employee's availability: call get_employee_availability_schedule with the employee_id and start_date/end_date set to the shift's local start date. Inspect the returned slots:
     - For each availability slot, check whether the SHIFT WINDOW (not the user's typed window) is fully contained: (slot.start_time <= shift_local_start) AND (slot.end_time >= shift_local_end). For overnight shifts where shift_local_end is on the next day, the slot must end at or after midnight of the next day — i.e. a normal daytime slot CANNOT cover an overnight shift.
     - For recurring slots, also confirm the day-of-week of the shift's local start date is in slot.days_of_week.
  3. Decision:
     - If at least one slot fully covers the SHIFT WINDOW → call assign_employee_to_shift with shift_id and employee_id.
     - If NO slot fully covers it → DO NOT call assign_employee_to_shift. Tell the user the employee is not available for the shift's full window (state the shift's actual hours, not the user's typed hours). List the employee's actual availability windows for that day. DO NOT propose assigning to a partial sub-window — partial assignments are not supported.
     - If the schedule tool returns no slots at all → say so honestly.
  4. Report the result. On a 'success: false' error from the assign tool (e.g. duplicate assignment), surface the error message to the user.

When refusing or confirming, always state the shift's ACTUAL hours from start_at/end_at — never echo the user's typed hours as if they were the shift's hours.

Enum values (use these EXACTLY — they are case-sensitive in some places):
- shift status: ACTIVE, INACTIVE, ARCHIVED (uppercase)
- shift_type: DAY, NIGHT, EVE (uppercase)
- recurrence_type: ONE_TIME, DAILY, WEEKLY (uppercase)
- employee shift status: SCHEDULED, CONFIRMED, CANCELLED, COMPLETED (uppercase)
- availability status: available, unavailable, tentative, booked (lowercase, fixture-only)
When in doubt, prefer uppercase for shift-related fields.

Rules:
- Always prefer calling a tool over guessing.
- Never invent results. If a tool returns nothing, say so honestly.
- If the user's request is ambiguous (missing date, employee, or shift name), ask a short clarifying question instead of inventing arguments.
- Use concise plain English in the final answer. Bullet lists for multiple items.
- Never expose raw UUIDs in the final answer unless the user explicitly asks for them.`;

const MAX_STEPS = 5;
const MODEL = 'gpt-4o-mini';

/**
 * Render the optional UI context object as a system-prompt block. The agent
 * uses these as defaults when the user's query omits a specific shift,
 * department, station, or date.
 */
function buildContextBlock(ctx?: SchedulingAgentContext): string | null {
  if (!ctx) return null;
  const lines: string[] = [];
  if (ctx.viewing) lines.push(`- viewing: ${ctx.viewing}`);
  if (ctx.date) lines.push(`- date: ${ctx.date}`);
  if (ctx.shiftName || ctx.shiftId) {
    const parts = [ctx.shiftName, ctx.shiftId ? `(id: ${ctx.shiftId})` : null]
      .filter(Boolean)
      .join(' ');
    lines.push(`- shift: ${parts}`);
  }
  if (ctx.departmentName || ctx.departmentId) {
    const parts = [ctx.departmentName, ctx.departmentId ? `(id: ${ctx.departmentId})` : null]
      .filter(Boolean)
      .join(' ');
    lines.push(`- department: ${parts}`);
  }
  if (ctx.stationName || ctx.stationId) {
    const parts = [ctx.stationName, ctx.stationId ? `(id: ${ctx.stationId})` : null]
      .filter(Boolean)
      .join(' ');
    lines.push(`- station: ${parts}`);
  }
  // Catch-all for any extra free-form keys the frontend passed.
  const known = new Set([
    'viewing',
    'date',
    'shiftId',
    'shiftName',
    'departmentId',
    'departmentName',
    'stationId',
    'stationName',
  ]);
  for (const [k, v] of Object.entries(ctx)) {
    if (known.has(k) || !v) continue;
    lines.push(`- ${k}: ${v}`);
  }
  if (lines.length === 0) return null;
  return [
    'Current page context (the user is looking at this on the frontend right now):',
    ...lines,
    '',
    'Treat these as DEFAULTS. When the user says "this shift", "this department", "today", or omits any of these fields, fall back to the values above. If a value above is a UUID, prefer it over calling search_shifts. If both a name and an id are given, use the id when calling tools.',
  ].join('\n');
}

export interface SchedulingAgentContext {
  /** Free-form label for the page or view (e.g. "employee-schedule-grid"). */
  viewing?: string;
  /** Date the user is looking at, ISO YYYY-MM-DD. */
  date?: string;
  /** Shift the user is looking at — name and/or UUID. */
  shiftId?: string;
  shiftName?: string;
  /** Department the user is looking at — id and/or name. */
  departmentId?: string;
  departmentName?: string;
  /** Station the user is looking at — id and/or name. */
  stationId?: string;
  stationName?: string;
  /** Catch-all for any extra free-form fields the frontend wants to pass. */
  [key: string]: string | undefined;
}

export interface SchedulingAgentRequest {
  userId: string;
  organizationId: string;
  query: string;
  context?: SchedulingAgentContext;
}

export interface SchedulingAgentToolCall {
  name: string;
  arguments: unknown;
  result: unknown;
}

export interface SchedulingAgentResponse {
  answer: string;
  toolCalls: SchedulingAgentToolCall[];
}

@Injectable()
export class SchedulingAgentService {
  private readonly logger = new Logger(SchedulingAgentService.name);

  constructor(
    private readonly mcpFactory: McpServerFactory,
    private readonly openai: OpenAiClient,
  ) {}

  async chat(req: SchedulingAgentRequest): Promise<SchedulingAgentResponse> {
    const tools = this.mcpFactory.buildSchedulingTools({
      organizationId: req.organizationId,
      userId: req.userId,
    });
    const openAiTools = toOpenAiTools(tools);
    const toolByName = new Map(tools.map((t) => [t.name, t]));

    const contextBlock = buildContextBlock(req.context);
    const systemContent = contextBlock ? `${SYSTEM_PROMPT}\n\n${contextBlock}` : SYSTEM_PROMPT;

    const messages: ChatCompletionMessageParam[] = [
      { role: 'system', content: systemContent },
      { role: 'user', content: req.query },
    ];
    const trace: SchedulingAgentToolCall[] = [];

    for (let step = 0; step < MAX_STEPS; step++) {
      const completion = await this.openai.client.chat.completions.create({
        model: MODEL,
        messages,
        tools: openAiTools,
        tool_choice: 'auto',
      });

      const msg = completion.choices[0].message;
      messages.push(msg);

      if (!msg.tool_calls?.length) {
        return { answer: msg.content ?? '', toolCalls: trace };
      }

      for (const call of msg.tool_calls) {
        const tool = toolByName.get(call.function.name);
        if (!tool) {
          messages.push({
            role: 'tool',
            tool_call_id: call.id,
            content: JSON.stringify({ error: 'tool_not_found', name: call.function.name }),
          });
          continue;
        }

        let args: unknown;
        try {
          args = JSON.parse(call.function.arguments || '{}');
        } catch {
          args = {};
        }

        try {
          const result = await tool.handler(args);
          const text = result.content[0]?.text ?? '';
          let parsed: unknown;
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = text;
          }
          trace.push({ name: tool.name, arguments: args, result: parsed });
          messages.push({
            role: 'tool',
            tool_call_id: call.id,
            content: text,
          });
        } catch (err) {
          this.logger.error(`Tool ${tool.name} failed`, err);
          messages.push({
            role: 'tool',
            tool_call_id: call.id,
            content: JSON.stringify({
              error: 'tool_execution_failed',
              message: err instanceof Error ? err.message : 'unknown',
            }),
          });
        }
      }
    }

    return {
      answer: 'I was unable to complete the request within the step limit.',
      toolCalls: trace,
    };
  }
}
