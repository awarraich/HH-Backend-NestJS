import { Module } from '@nestjs/common';
import { TypeOrmModule, TypeOrmModuleAsyncOptions } from '@nestjs/typeorm';
import { PostgresConfigModule } from '../../../config/database/postgres/config.module.js';
import { PostgresConfigService } from '../../../config/database/postgres/config.service.js';
import { migrations } from '../../../database/migrations/index.js';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [PostgresConfigModule],
      useFactory: (postgresConfigService: PostgresConfigService) => {
        const host = postgresConfigService.host;
        const isLocalhost = host === 'localhost' || host === '127.0.0.1';

        const sslConfig = process.env.DATABASE_SSL === 'true' && !isLocalhost
          ? { rejectUnauthorized: false }
          : false;

        return {
          type: 'postgres',
          host: postgresConfigService.host,
          port: postgresConfigService.port,
          username: postgresConfigService.username,
          password: postgresConfigService.password,
          database: postgresConfigService.database,
          synchronize: postgresConfigService.synchronize,
          logging: postgresConfigService.logging,
          migrationsRun: postgresConfigService.migrationsRun,
          migrations,
          entities: [
            'dist/src/**/*.entity.js',
            'dist/src/authentication/entities/*.entity.js',
            'dist/src/models/**/entities/*.entity.js',
          ],
          ssl: sslConfig,
        };
      },
      inject: [PostgresConfigService],
    } as TypeOrmModuleAsyncOptions),
  ],
})
export class PostgresDatabaseProviderModule {}