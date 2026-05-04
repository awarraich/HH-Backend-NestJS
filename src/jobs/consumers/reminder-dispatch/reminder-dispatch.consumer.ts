import { Logger } from '@nestjs/common';
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { NotificationDispatcherService } from '../../../models/notifications/services/notification-dispatcher.service';
import { REMINDER_DISPATCH_QUEUE } from '../../producers/reminder-dispatch/reminder-dispatch.producer';

@Processor(REMINDER_DISPATCH_QUEUE, {
  concurrency: 5,
  limiter: { max: 10, duration: 1000 },
})
export class ReminderDispatchConsumer extends WorkerHost {
  private readonly logger = new Logger(ReminderDispatchConsumer.name);

  constructor(private readonly dispatcher: NotificationDispatcherService) {
    super();
  }

  async process(job: Job): Promise<{ channel: string | null; status: string }> {
    const data = job.data as {
      orgId: string;
      userId: string;
      documentId: string;
      documentType: string;
      documentName: string;
      expiryDate: string;
      reminderKind: string;
    };

    this.logger.log(
      `Processing job ${job.id}: user=${data.userId} doc=${data.documentId} kind=${data.reminderKind}`,
    );

    const result = await this.dispatcher.dispatch({
      orgId: data.orgId,
      userId: data.userId,
      documentId: data.documentId,
      documentType: data.documentType,
      documentName: data.documentName,
      expiryDate: new Date(data.expiryDate),
      reminderKind: data.reminderKind as never,
    });

    if (result.status === 'failed') {
      throw new Error(result.error ?? 'dispatch failed');
    }

    return { channel: result.channel, status: result.status };
  }
}
