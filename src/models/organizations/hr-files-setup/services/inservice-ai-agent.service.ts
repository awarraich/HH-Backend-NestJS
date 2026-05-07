import { Injectable, Logger } from '@nestjs/common';
import { LlmRouter, type LlmMessage } from '../../../../common/services/llm';
import {
  InserviceNotificationService,
  type InserviceStatusReport,
  type InserviceGap,
} from './inservice-notification.service';

export interface AiAgentResponseCard {
  /** Hero summary line. */
  headline: string;
  /** One-paragraph explanation. */
  message: string;
  /** Severity used to colour the card. */
  severity: 'high' | 'medium' | 'low' | 'info';
  /** Optional bulleted next-steps list. */
  bullets?: string[];
  /** Inservices the AI is highlighting in this answer. */
  highlighted_inservices?: { title: string; reason: string; status: string }[];
}

export interface InserviceAiAgentResult {
  /** Plain LLM answer. Useful as a fallback when the structured card is missing. */
  answer: string;
  /** Structured card the frontend renders as the response widget. */
  card: AiAgentResponseCard;
  /** Snapshot of the gap report used to ground the LLM. */
  context: InserviceStatusReport;
}

const SYSTEM_PROMPT = `You are an HR compliance assistant embedded in an in-service training tracker. \
You answer questions about a single employee's in-service training gaps using only the JSON \
context provided. Always reply with a single valid JSON object matching this TypeScript type: \
{ "headline": string, "message": string, "severity": "high"|"medium"|"low"|"info", \
"bullets"?: string[], "highlighted_inservices"?: { "title": string, "reason": string, \
"status": string }[] }. Be concise (headline ≤ 80 chars, message ≤ 400 chars). Pick severity \
"high" when there are expired or missing trainings, "medium" for in-progress or expiring-soon, \
"low" when fully compliant. Never invent training names — only reference items present in the \
context. Do not include any text outside the JSON object.`;

@Injectable()
export class InserviceAiAgentService {
  private readonly logger = new Logger(InserviceAiAgentService.name);

  constructor(
    private readonly notificationService: InserviceNotificationService,
    private readonly llmRouter: LlmRouter,
  ) {}

  async ask(
    organizationId: string,
    employeeId: string,
    question: string,
  ): Promise<InserviceAiAgentResult> {
    const report = await this.notificationService.buildReport(organizationId, employeeId);

    const messages: LlmMessage[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      {
        role: 'user',
        content: [
          `Employee: ${report.employee_name}`,
          `Total required in-services: ${report.total_required}`,
          `Currently compliant: ${report.total_completed}`,
          `Open gaps: ${report.total_gaps} (${report.high_severity_count} high-severity)`,
          '',
          'Gap details (JSON):',
          JSON.stringify(report.gaps.map(slimGap), null, 2),
          '',
          'Compliant trainings (JSON):',
          JSON.stringify(report.completed_current, null, 2),
          '',
          `Question from HR: ${question}`,
        ].join('\n'),
      },
    ];

    let answer = '';
    let card: AiAgentResponseCard | null = null;
    try {
      const result = await this.llmRouter.generate(
        {
          messages,
          temperature: 0.2,
          maxTokens: 600,
          responseFormat: 'json_object',
        },
        { organizationId },
      );
      answer = result.message.content ?? '';
      card = this.tryParseCard(answer);
    } catch (err) {
      this.logger.warn(
        `LLM call failed for inservice AI agent (org=${organizationId}, emp=${employeeId}): ${
          err instanceof Error ? err.message : String(err)
        }. Falling back to deterministic summary.`,
      );
    }

    if (!card) {
      card = this.fallbackCard(report);
      if (!answer) answer = card.message;
    }

    return { answer, card, context: report };
  }

  private tryParseCard(raw: string): AiAgentResponseCard | null {
    if (!raw) return null;
    let text = raw.trim();
    // Defensive: some providers wrap JSON in code fences even when asked not to.
    if (text.startsWith('```')) {
      text = text.replace(/^```[a-z]*\n?/i, '').replace(/```\s*$/, '').trim();
    }
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object') return null;
      const obj = parsed as Record<string, unknown>;
      const headline = typeof obj.headline === 'string' ? obj.headline : null;
      const message = typeof obj.message === 'string' ? obj.message : null;
      const severityRaw = typeof obj.severity === 'string' ? obj.severity : 'info';
      if (!headline || !message) return null;
      const severity: AiAgentResponseCard['severity'] = ['high', 'medium', 'low', 'info'].includes(
        severityRaw,
      )
        ? (severityRaw as AiAgentResponseCard['severity'])
        : 'info';
      const bullets = Array.isArray(obj.bullets)
        ? obj.bullets.filter((b): b is string => typeof b === 'string').slice(0, 6)
        : undefined;
      const highlights = Array.isArray(obj.highlighted_inservices)
        ? obj.highlighted_inservices
            .map((h) => {
              if (!h || typeof h !== 'object') return null;
              const r = h as Record<string, unknown>;
              if (typeof r.title !== 'string') return null;
              return {
                title: r.title,
                reason: typeof r.reason === 'string' ? r.reason : '',
                status: typeof r.status === 'string' ? r.status : '',
              };
            })
            .filter((x): x is { title: string; reason: string; status: string } => x !== null)
            .slice(0, 8)
        : undefined;
      return { headline, message, severity, bullets, highlighted_inservices: highlights };
    } catch {
      return null;
    }
  }

  private fallbackCard(report: InserviceStatusReport): AiAgentResponseCard {
    if (report.total_gaps === 0) {
      return {
        headline: 'All in-services are current',
        message: `${report.employee_name} has completed all ${report.total_required} required in-service training(s) and none are expiring within 30 days.`,
        severity: 'low',
      };
    }
    const expired = report.gaps.filter((g) => g.status === 'expired').length;
    const missing = report.gaps.filter((g) => g.status === 'missing').length;
    const expiring = report.gaps.filter((g) => g.status === 'expiring_soon').length;
    const inProgress = report.gaps.filter((g) => g.status === 'in_progress').length;
    const severity: AiAgentResponseCard['severity'] =
      report.high_severity_count > 0 ? 'high' : 'medium';
    return {
      headline: `${report.total_gaps} in-service item${report.total_gaps === 1 ? '' : 's'} need attention`,
      message: `${expired} expired · ${missing} never started · ${expiring} expiring within 30 days · ${inProgress} in progress. Each in-service must be renewed at least once a year.`,
      severity,
      bullets: report.gaps.slice(0, 5).map((g) => `${g.title} — ${g.reason}`),
      highlighted_inservices: report.gaps.slice(0, 5).map((g) => ({
        title: g.title,
        reason: g.reason,
        status: g.status,
      })),
    };
  }
}

function slimGap(g: InserviceGap) {
  return {
    title: g.title,
    code: g.code,
    status: g.status,
    severity: g.severity,
    reason: g.reason,
    completed_at: g.completed_at,
    expiration_at: g.expiration_at,
    days_until_expiry: g.days_until_expiry,
    progress_percent: g.progress_percent,
  };
}
