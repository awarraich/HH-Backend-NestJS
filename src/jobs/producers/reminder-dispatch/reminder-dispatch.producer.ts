import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { DispatchInput } from '../../../models/notifications/services/notification-dispatcher.service';

export const REMINDER_DISPATCH_QUEUE = 'reminder-dispatch';
export const REMINDER_DISPATCH_JOB = 'dispatch';

interface SerializedDispatchInput extends Omit<DispatchInput, 'expiryDate'> {
  expiryDate: string;
}

@Injectable()
export class ReminderDispatchProducer {
  private readonly logger = new Logger(ReminderDispatchProducer.name);

  constructor(@InjectQueue(REMINDER_DISPATCH_QUEUE) private readonly queue: Queue) {}

  async enqueue(input: DispatchInput): Promise<void> {
    const payload: SerializedDispatchInput = {
      ...input,
      expiryDate: input.expiryDate.toISOString(),
    };
    const jobId = `${input.userId}:${input.documentId}:${input.reminderKind}`;
    await this.queue.add(REMINDER_DISPATCH_JOB, payload, {
      jobId,
      attempts: 3,
      backoff: { type: 'exponential', delay: 5000 },
      removeOnComplete: 1000,
      removeOnFail: 5000,
    });
    this.logger.log(`Enqueued dispatch ${jobId}`);
  }
}
