import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { OrganizationIntegration } from '../entities/organization-integration.entity';
import { ReminderKind } from '../entities/notification-dispatch-log.entity';
import { InserviceCompletion } from '../../organizations/hr-files-setup/entities/inservice-completion.entity';
import { ReminderDispatchProducer } from '../../../jobs/producers/reminder-dispatch/reminder-dispatch.producer';

interface CadenceEntry {
  kind: ReminderKind;
  days_before: number;
}

const DEFAULT_CADENCE: CadenceEntry[] = [
  { kind: '60d', days_before: 60 },
  { kind: '30d', days_before: 30 },
  { kind: '14d', days_before: 14 },
  { kind: '7d', days_before: 7 },
  { kind: '1d', days_before: 1 },
  { kind: 'expired', days_before: 0 },
];

export interface ScanResult {
  orgsScanned: number;
  candidatesFound: number;
  enqueued: number;
  malformed: number;
}

@Injectable()
export class DocumentExpiryScannerService {
  private readonly logger = new Logger(DocumentExpiryScannerService.name);

  constructor(
    @InjectRepository(OrganizationIntegration)
    private readonly orgIntegrations: Repository<OrganizationIntegration>,
    @InjectRepository(InserviceCompletion)
    private readonly completions: Repository<InserviceCompletion>,
    private readonly producer: ReminderDispatchProducer,
  ) {}

  @Cron('0 8 * * *', { name: 'document-expiry-scan' })
  async cronTick(): Promise<void> {
    this.logger.log('Daily expiry scan starting');
    const result = await this.runScan();
    this.logger.log(
      `Daily expiry scan done: orgs=${result.orgsScanned} candidates=${result.candidatesFound} ` +
        `enqueued=${result.enqueued} malformed=${result.malformed}`,
    );
  }

  /**
   * Walk every active org × cadence-entry × candidate document, and dispatch a
   * reminder for each match that hasn't already been sent. Pass `referenceDate`
   * to simulate "today" for testing; defaults to now.
   */
  async runScan(referenceDate: Date = new Date()): Promise<ScanResult> {
    const activeIntegrations = await this.orgIntegrations.find({
      where: { provider: 'google_chat', status: 'active' },
    });

    const result: ScanResult = {
      orgsScanned: activeIntegrations.length,
      candidatesFound: 0,
      enqueued: 0,
      malformed: 0,
    };

    for (const integration of activeIntegrations) {
      const cadence = this.getCadence(integration);

      for (const entry of cadence) {
        const window = this.dayWindow(referenceDate, entry.days_before);
        const candidates = await this.findInserviceCandidates(integration.org_id, window);

        result.candidatesFound += candidates.length;

        for (const c of candidates) {
          const userId = c.employee?.user_id;
          const trainingTitle = c.inserviceTraining?.title;
          if (!userId || !trainingTitle || !c.expiration_at) {
            this.logger.warn(
              `Skipping malformed completion ${c.id}: missing user_id / title / expiration_at`,
            );
            result.malformed++;
            continue;
          }

          await this.producer.enqueue({
            orgId: integration.org_id,
            userId,
            documentId: c.id,
            documentType: 'inservice_completion',
            documentName: trainingTitle,
            expiryDate: c.expiration_at,
            reminderKind: entry.kind,
          });
          result.enqueued++;
        }
      }
    }

    return result;
  }

  private getCadence(integration: OrganizationIntegration): CadenceEntry[] {
    const config = integration.config as { cadence?: ReminderKind[] } | null;
    if (!config?.cadence?.length) return DEFAULT_CADENCE;
    return DEFAULT_CADENCE.filter((e) => config.cadence!.includes(e.kind));
  }

  private dayWindow(referenceDate: Date, daysBefore: number): { start: Date; end: Date } {
    const target = new Date(referenceDate);
    target.setDate(target.getDate() + daysBefore);
    const start = new Date(target.getFullYear(), target.getMonth(), target.getDate());
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    return { start, end };
  }

  private async findInserviceCandidates(
    orgId: string,
    window: { start: Date; end: Date },
  ): Promise<InserviceCompletion[]> {
    return this.completions
      .createQueryBuilder('c')
      .innerJoinAndSelect('c.employee', 'e')
      .innerJoinAndSelect('c.inserviceTraining', 't')
      .where('e.organization_id = :orgId', { orgId })
      .andWhere('e.deleted_at IS NULL')
      .andWhere('c.expiration_at IS NOT NULL')
      .andWhere('c.expiration_at >= :start', { start: window.start })
      .andWhere('c.expiration_at < :end', { end: window.end })
      .getMany();
  }
}
