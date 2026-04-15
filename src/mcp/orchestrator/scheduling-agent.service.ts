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
- CRITICAL — "available" vs "assigned" are DIFFERENT:
  * An availability slot means the employee CAN work that window. It is NOT an assignment.
  * An assignment only exists as a row in employee_shifts. The availability tools return a \`current_assignments\` array on every record — this is the source of truth for "is this employee already booked on this shift?".
  * Before telling the user an employee is "already assigned" to a shift on a date, you MUST confirm a matching \`current_assignments\` entry exists (same shift_id + scheduled_date). If \`current_assignments\` is empty or does not match, the employee is AVAILABLE but NOT YET ASSIGNED.

CONFIRMATION PROTOCOL — read this before any assignment flow.
Tool results from previous turns are NOT replayed in your message history — only the text of your prior assistant messages is. If you tell the user "Would you like me to assign X to Y?" and stop, ALL UUIDs you learned this turn are lost. When the user then says "yes", you will have nothing to pass to assign_employee_to_shift and will be forced to either fabricate placeholder strings (FORBIDDEN) or re-run every discovery tool and hope the results are identical.
The ONLY way to carry UUIDs across turns is to embed them in your text response inside an HTML comment. The UI hides HTML comments from the user, but you will see them in the next turn's message history.
RULE: any assistant response that ends by asking the user to confirm an assignment (e.g. "Would you like to assign…?", "Shall I proceed?", "Confirm?") MUST include a trailing HTML comment of this exact shape:
  <!-- ASSIGNMENTS: [{"shift_id":"<uuid>","employee_id":"<uuid>","scheduled_date":"YYYY-MM-DD"},…] -->
One object per planned assignment. Real UUIDs only — never placeholders like "<uuid-for-…>". This applies to SLOW PATH (single employee), BULK PATH (many employees), and any ad-hoc confirmation you invent.
On the next turn, if the user confirms ("yes", "go ahead", "proceed", "confirm"), parse the ASSIGNMENTS block from your most recent assistant message in the history and call assign_employee_to_shift with those exact UUIDs and scheduled_dates. Do NOT re-run search_shifts / get_employee_availability / list_employees — the block is authoritative. Do NOT ask the user for names or IDs.
If a prior assistant turn asked for confirmation WITHOUT an ASSIGNMENTS block, you have no UUIDs to use. Do not fabricate them. Apologise briefly and re-run the discovery tools to rebuild the plan, then emit a fresh ASSIGNMENTS block and ask for confirmation again.

Assignment workflow (follow strictly when the user asks to "schedule", "assign", "book", or "put X on Y shift"):

  FAST PATH — if the user already provides BOTH a shift_id (UUID) AND an employee_id (UUID) AND a scheduled_date in the request:
    a. Call assign_employee_to_shift directly with the provided shift_id, employee_id, and scheduled_date, plus any optional fields they mention (department_id, station_id, room_id, bed_id, chair_id, notes, status).
    b. If the user mentions a role like "CHARGE NURSE", encode it into the notes field as JSON: notes='{"role":"CHARGE NURSE","rooms":[]}'.
    c. Report the tool's result. On 'success: false', surface the error verbatim.
    d. DO NOT call get_employee_shifts, get_shift_details, or any other read tool first. DO NOT report on the employee's prior assignments to other shifts — they are irrelevant.
    e. If the user provides shift_id and employee_id but NOT a scheduled_date and the shift is recurring, you MUST check the shift details and follow the SLOW PATH recurring-shift logic to determine which dates to assign.

  SLOW PATH — if the user gives a shift name (e.g. "NOC", "morning") instead of a shift_id:
  1. Resolve the Shift: call search_shifts with the keyword (e.g. "NOC", "morning"). If multiple matches, ask the user which one. If none, tell the user the shift doesn't exist. From the chosen shift, extract: shift_id, start_at, end_at, recurrence_type. Convert start_at/end_at to local time strings (HH:MM) and the local start date. Call this the SHIFT WINDOW.
  2. Check the employee's availability:
     - For ONE_TIME shifts: call get_employee_availability_schedule with the employee_id and start_date/end_date set to the shift's local start date.
     - For RECURRING shifts (FULL_WEEK, WEEKDAYS, WEEKENDS, CUSTOM): call get_employee_availability_schedule with the employee_id and NO date filter (omit start_date/end_date) to get ALL recurring availability slots. You need to check EACH day the shift recurs on.
  3. Inspect the returned slots:
     - For each availability slot, check whether the SHIFT WINDOW (not the user's typed window) is fully contained: (slot.start_time <= shift_local_start) AND (slot.end_time >= shift_local_end). For overnight shifts where shift_local_end is on the next day, the slot must end at or after midnight of the next day — i.e. a normal daytime slot CANNOT cover an overnight shift.
     - For recurring slots, match by day-of-week: the slot's days_of_week must include the day you are checking.
  4. Decision:
     - For ONE_TIME shifts: if at least one slot fully covers the SHIFT WINDOW → call assign_employee_to_shift with shift_id, employee_id, and scheduled_date set to the shift's local start date (YYYY-MM-DD). Only pause for confirmation if the user explicitly asked you to confirm first; if they already said "assign", just do it.
     - For RECURRING shifts: determine which days of the week the employee IS available AND the shift recurs on. The shift's recurrence_type tells you which days: FULL_WEEK = MON-SUN, WEEKDAYS = MON-FRI, WEEKENDS = SAT-SUN, CUSTOM = check recurrence_days field.
       * If the employee covers ALL recurrence days → tell the user the employee is available for all days and ask which dates to assign (or ask if they want a specific week).
       * If the employee covers SOME but not all days → tell the user which days are covered and which are not. Ask if they want to assign for just the covered days.
       * If the employee covers NO days → refuse the assignment and list the employee's actual availability.
     - When the user confirms which dates to assign, call assign_employee_to_shift ONCE PER DATE, passing scheduled_date (YYYY-MM-DD) for each call. Each call creates one assignment row for that specific date.
     - If NO slot fully covers the SHIFT WINDOW on any day → DO NOT call assign_employee_to_shift. Tell the user the employee is not available for the shift's full window (state the shift's actual hours). DO NOT propose assigning to a partial sub-window — partial assignments are not supported.
     - If the schedule tool returns no slots at all → say so honestly.
     - WHENEVER you stop to ask the user which date(s) / whether to proceed, you MUST append the ASSIGNMENTS HTML comment (see CONFIRMATION PROTOCOL above) listing every candidate {shift_id, employee_id, scheduled_date}. Without it, the next turn will have no UUIDs and the assignment will fail.
  5. Report the result. On a 'success: false' error from the assign tool (e.g. duplicate assignment), surface the error message to the user.

  BULK PATH — if the user asks to assign/plot/schedule multiple or all employees to shifts without naming specific employees (e.g. "plot my employees to available shifts", "auto-assign employees", "fill all shifts", "schedule everyone"):
  1. Gather shifts: call list_shifts (optionally filtered by date from the page context or user query) to get all available shift templates.
  2. Gather availability: call get_employee_availability with NO employee_id to get ALL employees' availability for the organization.
  3. Match: for each shift, determine which employees have an availability slot that fully covers the shift's time window (same containment rules as the SLOW PATH). An employee's availability slot must fully contain the shift window. For recurring shifts, match per day-of-week — an employee is only matched to the specific days their availability covers.
  4. Present the plan: show the user a summary of proposed assignments — which employee → which shift → which date(s) — and ask for confirmation before making any assignments. Format as a bullet list grouped by shift.
     CRITICAL: In your plan response, you MUST include the actual UUIDs AND scheduled_dates for each proposed pairing in a machine-readable block at the end, like this:
     <!-- ASSIGNMENTS: [{"shift_id":"<uuid>","employee_id":"<uuid>","scheduled_date":"YYYY-MM-DD"},…] -->
     This is essential because tool results from this turn will NOT be available in the next turn. The only way to preserve the UUIDs is to embed them in your text response. The HTML comment keeps them hidden from the user while remaining accessible to you in conversation history.
  5. On confirmation (user says "yes", "go ahead", "proceed", etc.): read the ASSIGNMENTS block from your previous message in the conversation history. Call assign_employee_to_shift for each pairing using those exact UUIDs and scheduled_dates. Do NOT re-call get_employee_availability or get_employee_availability_schedule — the availability was already verified in step 3. Do NOT ask the user for employee names or IDs.
  6. If no employees are available for a shift, say so honestly for that shift.
  IMPORTANT: NEVER ask the user to provide employee names or IDs when they have asked for a bulk/auto-assignment. Use the tools to look up employees and their availability yourself.

When refusing or confirming, always state the shift's ACTUAL hours from start_at/end_at — never echo the user's typed hours as if they were the shift's hours.

Enum values (use these EXACTLY — they are case-sensitive in some places):
- shift status: ACTIVE, INACTIVE, ARCHIVED (uppercase)
- shift_type: DAY, NIGHT, EVE (uppercase)
- recurrence_type: ONE_TIME, FULL_WEEK, WEEKDAYS, WEEKENDS, CUSTOM (uppercase)
- employee shift status: SCHEDULED, CONFIRMED, CANCELLED, COMPLETED (uppercase)
- availability status: available, unavailable, tentative, booked (lowercase, fixture-only)
When in doubt, prefer uppercase for shift-related fields.

Availability queries (CRITICAL — pick the right tool):

  USER: "what are the availabilities for my employees?" / "show all availability" / "who is available?"
  CORRECT: call get_employee_availability with NO employee_id. It returns ALL employees' availability for the organization.
  WRONG: calling get_employee_availability_schedule for each employee — that tool requires a real UUID and is for ONE specific employee.

  USER: "what is Ahmad's availability?" / "show availability for employee X"
  CORRECT: first call search_employees to get the real employee_id UUID, then call get_employee_availability_schedule with that UUID.
  WRONG: inventing an employee_id like "ahmad_khan_id" — NEVER guess or fabricate UUIDs. Always resolve names to real UUIDs via search_employees first.

  CRITICAL: NEVER invent or fabricate employee_id values. Strings like "uuid-for-lvn-ahmad-khan" or "ahmad_khan_rn_id" are NOT valid UUIDs. If you need an employee_id, call search_employees or list_employees to get the real UUID.

Rules:
- Always prefer calling a tool over guessing.
- Never invent results. If a tool returns nothing, say so honestly.
- NEVER invent or guess UUIDs for any tool parameter. Always resolve names to real IDs via search_employees, search_shifts, or search_roles first.
- If the user's request is ambiguous (missing date, employee, or shift name), ask a short clarifying question instead of inventing arguments.
- Use concise plain English in the final answer. Bullet lists for multiple items.
- Never expose raw UUIDs in the visible part of your answer. Always refer to people and shifts by NAME using the \`employee_name\` or shift \`name\` field from tool results. The phrase "Employee 1", "Employee 2", or "Employee bb41…" must NEVER appear in your reply — if a tool result lacks a name, call search_employees to resolve it before answering. Exception: you MUST embed UUIDs in an HTML comment block (<!-- ASSIGNMENTS: [...] -->) whenever your reply asks the user to confirm an assignment, per the CONFIRMATION PROTOCOL. This applies to SLOW PATH, BULK PATH, and any ad-hoc confirmation flow.

Conversation memory and back-references:
- You receive prior conversation turns in the messages array. Read them. The user's current message often refers to entities mentioned in earlier turns ("this shift", "that employee", "the one we just assigned", "the NOC shift from before").
- When the user uses a demonstrative ("this", "that", "the", "it") without naming the entity, look back through the conversation history and pick the most recently discussed shift / employee / role. DO NOT ask "which shift?" if the answer is obvious from the previous turn.
- After a successful assignment (assign_employee_to_shift returned success: true), remember it. If the user asks "is anyone assigned to this shift?" in a later turn, the answer must include the assignment you just made — even if you have to call get_shift_details again to confirm.
- If a tool result you got 30 seconds ago is still fresh (same conversation, same entity), prefer answering from memory over re-calling the tool. Re-call only when the user asks for fresh data ("refresh", "check again") or when state may have changed because of a write you made.

Role-based queries (CRITICAL — pick the right tool):

Routing examples — match these EXACTLY:

  USER: "give me employees with roles"
  CORRECT: call list_employees (no args). The response includes each
  employee's provider_role via JOIN. List them by name with their role.
  WRONG: calling list_employees_by_role_name with role_name="role" or
  role_name="with roles" — that tool will REJECT generic words.

  USER: "give me employees and their roles"
  CORRECT: call list_employees.

  USER: "show me all staff"
  CORRECT: call list_employees.

  USER: "who works here?"
  CORRECT: call list_employees.

  USER: "list employees"
  CORRECT: call list_employees.

  USER: "what employees are RNs?"
  CORRECT: call list_employees_by_role_name with role_name="RN".

  USER: "list all OT employees"
  CORRECT: call list_employees_by_role_name with role_name="OT".

  USER: "who has the Sitter role?"
  CORRECT: call list_employees_by_role_name with role_name="Sitter".

Decision rule:
  - Does the user's message contain a specific role keyword (RN, OT, CNA,
    Sitter, Nurse, Therapist, etc.)? → list_employees_by_role_name
  - Otherwise → list_employees (it includes provider_role on every row).

Forbidden behaviors:
- NEVER call list_employees_by_role_name with a generic word like "role",
  "roles", "any", "all", or with the user's literal phrase "with roles".
  Those are not role names. If you do not have a specific role keyword,
  use list_employees instead.
- NEVER answer "no employees in role X" when list_employees_by_role_name
  returned a non-empty 'employees' array. Read the count and the
  employees[] array before composing your reply.
- NEVER contradict a fact you established one or two turns ago. If the
  conversation history shows "Ahmad Khan — OT", do not respond "no
  employees in OT" without first re-running list_employees_by_role_name
  AND reading its 'employees' array carefully.

list_employees_by_role_name details:
- Single SQL join under the hood (employees ⨝ provider_roles). Whatever
  role the employee actually points to in the database is what gets
  matched — there is no two-step lookup that can drift.
- Uses exact-first matching: "OT" matches the OT row, not COTA. "RN"
  matches RN. Falls back to fuzzy substring only if exact match returns
  nothing.
- Returns: count, matched_roles, employees[]. If count > 0, you MUST
  list those employees in your reply by their full name.

Cross-checking with prior turns:
- If a prior turn established an employee/role pairing and the current
  tool result contradicts it, re-read the current result carefully before
  answering. If the contradiction is real, tell the user there is a data
  inconsistency rather than confidently denying yourself.`;

const MAX_STEPS = 12;
const MODEL = 'gpt-4o-mini';

/**
 * Render the optional UI context object as a system-prompt block. The agent
 * uses these as defaults when the user's query omits a specific shift,
 * department, station, or date.
 */
/**
 * Tell the LLM what "today" is in the user's local timezone. Without this,
 * GPT happily guesses dates based on its training-era clock and can pick
 * yesterday (or an arbitrary nearby day) when the user asks to schedule
 * "this week" without giving a specific date. That produces assignments
 * against the wrong weekday, which then get rejected by the availability
 * check in assign_employee_to_shift.
 */
function buildTodayBlock(timezone?: string): string {
  const tz = timezone && timezone.trim() ? timezone : 'UTC';
  let today: string;
  let weekday: string;
  try {
    const fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      weekday: 'long',
    });
    const parts = fmt.formatToParts(new Date());
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
    today = `${get('year')}-${get('month')}-${get('day')}`;
    weekday = get('weekday');
  } catch {
    const now = new Date();
    today = now.toISOString().slice(0, 10);
    weekday = now.toUTCString().slice(0, 3);
  }
  return [
    `Today's date is ${today} (${weekday}) in timezone ${tz}.`,
    'When the user does not specify a date, default to today. When they say "this week" or "the coming week", use the 7-day window starting at today. NEVER schedule an assignment for a date before today without explicit user confirmation.',
    'For a recurring shift, when picking which specific date(s) to assign an employee to, pick the NEXT calendar date on or after today whose day-of-week matches the employee\'s availability. Do not pick yesterday.',
  ].join('\n');
}

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

/**
 * Flatten the prior turn's tool-call trace into a compact system message so
 * the LLM sees raw UUIDs from the last turn's discoveries even if they were
 * not embedded in the assistant's text via the ASSIGNMENTS HTML comment.
 *
 * Bounded: at most the last 12 calls, each result truncated to 2000 chars,
 * to keep the prompt cheap on "yes"-style confirmation turns where the
 * client may have sent us a very long trace.
 */
function buildPriorToolCallsBlock(
  calls: SchedulingAgentToolCall[] | undefined,
): string | null {
  if (!calls?.length) return null;
  const recent = calls.slice(-12);
  const lines: string[] = [
    'Prior-turn tool results (most recent call last). These are authoritative for any UUID or field you need to reference in the current turn. Prefer these over re-running discovery tools:',
  ];
  for (const c of recent) {
    const args = safeStringify(c.arguments, 500);
    const result = safeStringify(c.result, 2000);
    lines.push(`- ${c.name}(${args}) → ${result}`);
  }
  return lines.join('\n');
}

function safeStringify(value: unknown, maxLen: number): string {
  let text: string;
  try {
    text = typeof value === 'string' ? value : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (text.length > maxLen) return text.slice(0, maxLen) + '…';
  return text;
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

/**
 * One turn of prior conversation, sent by the client on every request so
 * the agent has multi-turn memory. Keep it lean: text-only, no tool traces.
 * The frontend should cap history at the last ~20 turns to bound payload size.
 */
export interface SchedulingAgentHistoryMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface SchedulingAgentRequest {
  userId: string;
  organizationId: string;
  query: string;
  context?: SchedulingAgentContext;
  /**
   * Prior conversation turns in chronological order (oldest first), excluding
   * the current `query`. The service inserts these between the system prompt
   * and the current user message so the LLM can resolve back-references like
   * "this shift", "that employee", "the one we just assigned".
   */
  history?: SchedulingAgentHistoryMessage[];
  /**
   * Tool-call trace from the IMMEDIATELY PRIOR turn, as returned in the
   * previous response's `toolCalls` field. The service converts these into
   * a synthetic system message so the LLM can see prior tool results
   * (including UUIDs) without us having to rehydrate OpenAI-native tool
   * messages with strict tool_call_id matching.
   * Belt-and-suspenders for the cross-turn UUID loss problem: even if the
   * LLM forgot to embed the ASSIGNMENTS HTML comment, the raw UUIDs from
   * prior tool results are still reachable here.
   */
  priorToolCalls?: SchedulingAgentToolCall[];
  /**
   * Client-supplied IANA timezone, e.g. "Asia/Karachi".
   * The browser provides this for free via
   * `Intl.DateTimeFormat().resolvedOptions().timeZone`. Optional — falls
   * back to UTC at the factory boundary if missing or invalid.
   */
  timezone?: string;
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
      timezone: req.timezone,
      departmentId: req.context?.departmentId,
      stationId: req.context?.stationId,
      roomId: req.context?.roomId,
      bedId: req.context?.bedId,
      chairId: req.context?.chairId,
    });
    const openAiTools = toOpenAiTools(tools);
    const toolByName = new Map(tools.map((t) => [t.name, t]));

    const contextBlock = buildContextBlock(req.context);
    const todayBlock = buildTodayBlock(req.timezone);
    const systemContent = [SYSTEM_PROMPT, todayBlock, contextBlock]
      .filter(Boolean)
      .join('\n\n');

    // Build the conversation: [system, ...history, (priorToolContext?), user query]
    // History gives the LLM multi-turn memory so it can resolve references
    // like "this shift" or "the one we just assigned".
    const historyMessages: ChatCompletionMessageParam[] = (req.history ?? [])
      .filter((m) => m && typeof m.content === 'string' && m.content.trim().length > 0)
      .map((m) => ({ role: m.role, content: m.content }));

    const messages: ChatCompletionMessageParam[] = [
      { role: 'system', content: systemContent },
      ...historyMessages,
    ];

    // Cross-turn UUID rescue: if the client replayed the prior turn's tool
    // trace, flatten it into one system message right before the user's
    // query. This way the LLM can read real UUIDs from prior tool results
    // even if it forgot to embed them in the ASSIGNMENTS HTML comment.
    const priorBlock = buildPriorToolCallsBlock(req.priorToolCalls);
    if (priorBlock) {
      messages.push({ role: 'system', content: priorBlock });
    }

    messages.push({ role: 'user', content: req.query });
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
        this.logger.debug(
          `agent finished in ${step + 1} step(s); ${trace.length} tool call(s): ${trace.map((t) => t.name).join(', ') || '(none)'}`,
        );
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
          this.logger.debug(
            `[step ${step}] tool_call ${tool.name} args=${JSON.stringify(args)} result=${text.slice(0, 2000)}`,
          );
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
