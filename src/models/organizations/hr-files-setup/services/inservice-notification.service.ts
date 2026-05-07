import { Injectable, Logger, NotFoundException, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository, IsNull } from 'typeorm';
import { Employee } from '../../../employees/entities/employee.entity';
import { User } from '../../../../authentication/entities/user.entity';
import { InserviceTraining } from '../entities/inservice-training.entity';
import { InserviceCompletion } from '../entities/inservice-completion.entity';
import { EmployeeRequirementTag } from '../entities/employee-requirement-tag.entity';
import { RequirementInserviceTraining } from '../entities/requirement-inservice-training.entity';
import { EmailService } from '../../../../common/services/email/email.service';

export type InserviceGapStatus =
  | 'missing'
  | 'in_progress'
  | 'expired'
  | 'expiring_soon';

export interface InserviceGap {
  inservice_training_id: string;
  code: string;
  title: string;
  description: string | null;
  completion_frequency: string;
  expiry_months: number | null;
  status: InserviceGapStatus;
  progress_percent: number;
  completed_at: string | null;
  expiration_at: string | null;
  /** Days until the inservice expires (negative if already expired). */
  days_until_expiry: number | null;
  severity: 'high' | 'medium' | 'low';
  reason: string;
}

export interface InserviceStatusReport {
  employee_id: string;
  organization_id: string;
  employee_name: string;
  employee_email: string;
  total_required: number;
  total_completed: number;
  total_gaps: number;
  high_severity_count: number;
  /** All inservices the employee has gaps on (missing / in-progress / expired / about to expire). */
  gaps: InserviceGap[];
  /** Inservices that are completed and not expiring within the alert window. */
  completed_current: { inservice_training_id: string; title: string; completed_at: string }[];
  generated_at: string;
}

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
/** Inservices that expire within this many days surface as "expiring soon". */
const EXPIRY_ALERT_WINDOW_DAYS = 30;
/** Default expiry window for trainings that don't specify expiry_months — 1 year. */
const DEFAULT_EXPIRY_MONTHS = 12;

@Injectable()
export class InserviceNotificationService implements OnModuleInit {
  private readonly logger = new Logger(InserviceNotificationService.name);
  private cronTimer: NodeJS.Timeout | null = null;

  constructor(
    @InjectRepository(Employee)
    private readonly employeeRepository: Repository<Employee>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(InserviceTraining)
    private readonly inserviceTrainingRepository: Repository<InserviceTraining>,
    @InjectRepository(InserviceCompletion)
    private readonly completionRepository: Repository<InserviceCompletion>,
    @InjectRepository(EmployeeRequirementTag)
    private readonly employeeRequirementTagRepository: Repository<EmployeeRequirementTag>,
    @InjectRepository(RequirementInserviceTraining)
    private readonly requirementInserviceTrainingRepository: Repository<RequirementInserviceTraining>,
    private readonly emailService: EmailService,
  ) {}

  onModuleInit(): void {
    // Lightweight in-process scheduler — re-checks every employee once per
    // 24h and emails anyone with a high-severity gap (missing, expired, or
    // expiring within 30 days). Avoids the @nestjs/schedule dependency.
    const runDaily = () => {
      this.runDailyExpiryScan().catch((err) => {
        this.logger.error('Daily inservice expiry scan failed', err as Error);
      });
    };
    // First run 60s after boot, then every 24h.
    setTimeout(runDaily, 60_000);
    this.cronTimer = setInterval(runDaily, ONE_DAY_MS);
  }

  async buildReport(
    organizationId: string,
    employeeId: string,
  ): Promise<InserviceStatusReport> {
    const employee = await this.employeeRepository.findOne({
      where: { id: employeeId, organization_id: organizationId, deleted_at: IsNull() },
    });
    if (!employee) {
      throw new NotFoundException(`Employee ${employeeId} not found in organization ${organizationId}.`);
    }

    const user = await this.userRepository.findOne({ where: { id: employee.user_id } });
    const employeeName = user ? `${user.firstName} ${user.lastName}`.trim() : 'Employee';
    const employeeEmail = user?.email ?? '';

    const tags = await this.employeeRequirementTagRepository.find({
      where: { employee_id: employeeId },
      select: ['requirement_tag_id'],
    });
    const tagIds = tags.map((t) => t.requirement_tag_id);

    let requiredTrainings: InserviceTraining[] = [];
    if (tagIds.length > 0) {
      const links = await this.requirementInserviceTrainingRepository.find({
        where: { requirement_tag_id: In(tagIds) },
        select: ['inservice_training_id'],
      });
      const inserviceIds = [...new Set(links.map((l) => l.inservice_training_id))];
      if (inserviceIds.length > 0) {
        requiredTrainings = await this.inserviceTrainingRepository.find({
          where: {
            id: In(inserviceIds),
            organization_id: organizationId,
            is_active: true,
          },
        });
      }
    }

    const completions = requiredTrainings.length
      ? await this.completionRepository.find({
          where: {
            employee_id: employeeId,
            inservice_training_id: In(requiredTrainings.map((t) => t.id)),
          },
        })
      : [];
    const completionByTrainingId = new Map<string, InserviceCompletion>();
    for (const c of completions) completionByTrainingId.set(c.inservice_training_id, c);

    const now = new Date();
    const gaps: InserviceGap[] = [];
    const completedCurrent: { inservice_training_id: string; title: string; completed_at: string }[] = [];

    for (const training of requiredTrainings) {
      const completion = completionByTrainingId.get(training.id) ?? null;
      const gap = this.classify(training, completion, now);
      if (gap) {
        gaps.push(gap);
      } else if (completion?.completed_at) {
        completedCurrent.push({
          inservice_training_id: training.id,
          title: training.title,
          completed_at: completion.completed_at.toISOString(),
        });
      }
    }

    gaps.sort((a, b) => {
      const sev = (s: InserviceGap['severity']) => (s === 'high' ? 0 : s === 'medium' ? 1 : 2);
      const diff = sev(a.severity) - sev(b.severity);
      if (diff !== 0) return diff;
      return (a.days_until_expiry ?? 9999) - (b.days_until_expiry ?? 9999);
    });

    return {
      employee_id: employeeId,
      organization_id: organizationId,
      employee_name: employeeName,
      employee_email: employeeEmail,
      total_required: requiredTrainings.length,
      total_completed: completedCurrent.length,
      total_gaps: gaps.length,
      high_severity_count: gaps.filter((g) => g.severity === 'high').length,
      gaps,
      completed_current: completedCurrent,
      generated_at: now.toISOString(),
    };
  }

  /** Classifies a single training; returns null when the completion is fully current. */
  private classify(
    training: InserviceTraining,
    completion: InserviceCompletion | null,
    now: Date,
  ): InserviceGap | null {
    const expiryMonths = training.expiry_months ?? DEFAULT_EXPIRY_MONTHS;

    const base = {
      inservice_training_id: training.id,
      code: training.code,
      title: training.title,
      description: training.description,
      completion_frequency: training.completion_frequency,
      expiry_months: training.expiry_months,
    };

    if (!completion || !completion.completed_at) {
      const inProgress = !!completion && completion.progress_percent > 0;
      return {
        ...base,
        status: inProgress ? 'in_progress' : 'missing',
        progress_percent: completion?.progress_percent ?? 0,
        completed_at: null,
        expiration_at: null,
        days_until_expiry: null,
        severity: inProgress ? 'medium' : 'high',
        reason: inProgress
          ? `Started but not finished (${completion?.progress_percent ?? 0}% complete).`
          : 'Has never been completed by this employee.',
      };
    }

    // Effective expiration: stored value if present, otherwise computed from
    // completed_at + expiry_months (defaulting to 12 months when missing).
    let expirationAt = completion.expiration_at ?? null;
    if (!expirationAt && expiryMonths > 0) {
      const exp = new Date(completion.completed_at);
      exp.setMonth(exp.getMonth() + expiryMonths);
      expirationAt = exp;
    }

    const completedAtIso = completion.completed_at.toISOString();
    if (!expirationAt) {
      // one_time training that never expires — fully current.
      return null;
    }

    const daysUntilExpiry = Math.floor((expirationAt.getTime() - now.getTime()) / ONE_DAY_MS);

    if (daysUntilExpiry < 0) {
      return {
        ...base,
        status: 'expired',
        progress_percent: 100,
        completed_at: completedAtIso,
        expiration_at: expirationAt.toISOString(),
        days_until_expiry: daysUntilExpiry,
        severity: 'high',
        reason: `Expired ${Math.abs(daysUntilExpiry)} day(s) ago — must be renewed.`,
      };
    }
    if (daysUntilExpiry <= EXPIRY_ALERT_WINDOW_DAYS) {
      return {
        ...base,
        status: 'expiring_soon',
        progress_percent: 100,
        completed_at: completedAtIso,
        expiration_at: expirationAt.toISOString(),
        days_until_expiry: daysUntilExpiry,
        severity: daysUntilExpiry <= 7 ? 'high' : 'medium',
        reason: `Expires in ${daysUntilExpiry} day(s).`,
      };
    }
    return null;
  }

  /**
   * Sends a notification email to the employee summarizing missing,
   * expired, or expiring-soon inservices. Returns the report so the
   * caller can show the user what was sent.
   */
  async notifyEmployee(
    organizationId: string,
    employeeId: string,
    options: { trainingId?: string } = {},
  ): Promise<{ report: InserviceStatusReport; emailSent: boolean; reason?: string }> {
    const report = await this.buildReport(organizationId, employeeId);

    // Optionally narrow the reminder to a single training (used by the
    // per-row "Send Reminder" button on the inservices list). If the
    // caller asked about a training that *isn't* a gap, we still send a
    // reminder so HR's intent is honored — the email just contains that
    // single item with a generic prompt to renew/refresh.
    let scoped = report;
    if (options.trainingId) {
      const matched = report.gaps.find((g) => g.inservice_training_id === options.trainingId);
      if (matched) {
        scoped = {
          ...report,
          gaps: [matched],
          total_gaps: 1,
          high_severity_count: matched.severity === 'high' ? 1 : 0,
        };
      } else {
        // Look up the training to include its title in the message.
        const training = await this.inserviceTrainingRepository.findOne({
          where: { id: options.trainingId, organization_id: organizationId },
        });
        if (!training) {
          return {
            report,
            emailSent: false,
            reason: 'Training not found for this organization.',
          };
        }
        const placeholder: InserviceGap = {
          inservice_training_id: training.id,
          code: training.code,
          title: training.title,
          description: training.description,
          completion_frequency: training.completion_frequency,
          expiry_months: training.expiry_months,
          status: 'missing',
          progress_percent: 0,
          completed_at: null,
          expiration_at: null,
          days_until_expiry: null,
          severity: 'medium',
          reason: 'HR sent a reminder to complete this training.',
        };
        scoped = {
          ...report,
          gaps: [placeholder],
          total_gaps: 1,
          high_severity_count: 0,
        };
      }
    }

    if (scoped.gaps.length === 0) {
      return {
        report: scoped,
        emailSent: false,
        reason: 'No gaps to notify about — employee is fully compliant.',
      };
    }
    if (!scoped.employee_email) {
      return {
        report: scoped,
        emailSent: false,
        reason: 'Employee has no email address on file.',
      };
    }

    try {
      await this.sendInserviceReminderEmail(scoped);
      return { report: scoped, emailSent: true };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Failed to send inservice reminder to ${scoped.employee_email}: ${msg}`,
        err instanceof Error ? err.stack : undefined,
      );
      return { report: scoped, emailSent: false, reason: `Email send failed: ${msg}` };
    }
  }

  /**
   * Cron-style daily scan: walks every employee in every organization and
   * sends a reminder when there is at least one high-severity gap. Logs
   * and continues on per-employee failures so one bad row doesn't kill
   * the whole sweep.
   */
  async runDailyExpiryScan(): Promise<void> {
    const employees = await this.employeeRepository.find({
      where: { deleted_at: IsNull(), status: 'active' },
      select: ['id', 'organization_id'],
    });

    let sent = 0;
    let skipped = 0;
    for (const emp of employees) {
      if (!emp.organization_id) continue;
      try {
        const result = await this.notifyEmployee(emp.organization_id, emp.id);
        if (result.report.high_severity_count > 0 && result.emailSent) sent++;
        else skipped++;
      } catch (err) {
        this.logger.warn(
          `Skipping employee ${emp.id} during daily scan: ${err instanceof Error ? err.message : String(err)}`,
        );
        skipped++;
      }
    }
    this.logger.log(
      `Daily inservice expiry scan complete: ${sent} reminder(s) sent, ${skipped} skipped.`,
    );
  }

  private async sendInserviceReminderEmail(report: InserviceStatusReport): Promise<void> {
    const subject = `Action required: ${report.total_gaps} in-service training${report.total_gaps === 1 ? '' : 's'} need attention`;

    const groupBy = (status: InserviceGapStatus) => report.gaps.filter((g) => g.status === status);
    const missing = groupBy('missing');
    const expired = groupBy('expired');
    const expiring = groupBy('expiring_soon');
    const inProgress = groupBy('in_progress');

    const renderRow = (g: InserviceGap) =>
      `<tr><td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">
        <div style="font-weight:600;color:#111827;">${escapeHtml(g.title)}</div>
        <div style="font-size:12px;color:#6b7280;margin-top:2px;">${escapeHtml(g.reason)}</div>
      </td></tr>`;

    const renderSection = (label: string, color: string, items: InserviceGap[]) => {
      if (items.length === 0) return '';
      return `<div style="margin:18px 0;">
        <div style="display:inline-block;background:${color};color:white;padding:4px 10px;border-radius:6px;font-size:12px;font-weight:600;letter-spacing:0.3px;text-transform:uppercase;">${escapeHtml(label)} (${items.length})</div>
        <table style="width:100%;border-collapse:collapse;margin-top:8px;">${items.map(renderRow).join('')}</table>
      </div>`;
    };

    const html = `<!DOCTYPE html>
<html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f9fafb;margin:0;padding:24px;">
  <table style="max-width:640px;margin:0 auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08);">
    <tr><td style="padding:24px 28px;background:linear-gradient(135deg,#1f2937,#374151);color:white;">
      <div style="font-size:20px;font-weight:700;">In-Service Training Reminder</div>
      <div style="opacity:0.8;font-size:13px;margin-top:4px;">Hi ${escapeHtml(report.employee_name)}, a few items need your attention.</div>
    </td></tr>
    <tr><td style="padding:20px 28px;">
      <p style="color:#374151;line-height:1.55;margin:0 0 12px;">Our records show <strong>${report.total_gaps}</strong> in-service training${report.total_gaps === 1 ? '' : 's'} that are missing, expired, or about to expire. Each in-service must be renewed at least once a year. Please complete the items below to keep your file current.</p>
      ${renderSection('Expired', '#dc2626', expired)}
      ${renderSection('Missing', '#ea580c', missing)}
      ${renderSection('Expiring soon', '#d97706', expiring)}
      ${renderSection('In progress', '#2563eb', inProgress)}
      <p style="color:#6b7280;font-size:12px;margin-top:24px;">If you've already completed any of these, log in to upload your certificate or finish the quiz so your record updates automatically.</p>
    </td></tr>
  </table>
</body></html>`;

    const textLines = [
      `Hi ${report.employee_name},`,
      '',
      `You have ${report.total_gaps} in-service training(s) that need attention. Each in-service must be renewed at least once a year.`,
      '',
      ...report.gaps.map((g) => `- [${g.status.toUpperCase()}] ${g.title}: ${g.reason}`),
      '',
      'Please log in to complete the outstanding items.',
    ];

    await this.emailService.sendCustomNotificationEmail({
      toEmail: report.employee_email,
      subject,
      html,
      text: textLines.join('\n'),
    });
    this.logger.log(`Inservice reminder sent to ${report.employee_email} (${report.total_gaps} gap(s))`);
  }
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
