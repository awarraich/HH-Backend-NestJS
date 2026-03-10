import { Module } from '@nestjs/common';
import { CacheConfigModule } from '../../../config/cache/config.module';
import { CacheConfigService } from '../../../config/cache/config.service';

// Note: Install @nestjs/cache-manager and cache-manager-redis-store for full implementation
// npm install @nestjs/cache-manager cache-manager cache-manager-redis-store

@Module({
  imports: [CacheConfigModule],
  providers: [
    {
      provide: 'CACHE_CONFIG',
      useFactory: (
        cacheConfigService: CacheConfigService,
      ): { host: string; port: number; password: string; ttl: number } => ({
        host: cacheConfigService.host,
        port: cacheConfigService.port,
        password: cacheConfigService.password,
        ttl: cacheConfigService.ttl,
      }),
      inject: [CacheConfigService],
    },
  ],
  exports: ['CACHE_CONFIG'],
})
export class RedisCacheProviderModule {}
