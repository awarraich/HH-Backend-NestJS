import { Module } from '@nestjs/common';
import { QueueConfigModule } from '../../../config/queue/config.module';
import { QueueConfigService } from '../../../config/queue/config.service';

// Note: Install @nestjs/bull and bull for full implementation
// npm install @nestjs/bull bull

@Module({
  imports: [QueueConfigModule],
  providers: [
    {
      provide: 'QUEUE_CONFIG',
      useFactory: (
        queueConfigService: QueueConfigService,
      ): { host: string; port: number; password: string } => ({
        host: queueConfigService.host,
        port: queueConfigService.port,
        password: queueConfigService.password,
      }),
      inject: [QueueConfigService],
    },
  ],
  exports: ['QUEUE_CONFIG'],
})
export class RedisQueueProviderModule {}
