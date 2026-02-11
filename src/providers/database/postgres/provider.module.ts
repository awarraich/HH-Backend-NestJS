import { Module } from '@nestjs/common';
import { TypeOrmModule, TypeOrmModuleAsyncOptions } from '@nestjs/typeorm';
import { PostgresConfigModule } from '../../../config/database/postgres/config.module.js';
import { PostgresConfigService } from '../../../config/database/postgres/config.service.js';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [PostgresConfigModule],
      useFactory: async (postgresConfigService: PostgresConfigService) => {
        const isProduction = process.env.NODE_ENV === 'production';
        const host = postgresConfigService.host;
        const isLocalhost = host === 'localhost' || host === '127.0.0.1';
        
        let sslConfig: boolean | object = false;
        
        if (isProduction && !isLocalhost) {
          // Remote database - check if SSL certificates are provided
          const sslCa = process.env.DB_SSL_CA;
          const sslCert = process.env.DB_SSL_CERT;
          const sslKey = process.env.DB_SSL_KEY;
          
          if (sslCa || sslCert || sslKey) {
            // SSL certificates provided - use them
            sslConfig = {
              rejectUnauthorized: true,
              ...(sslCa && { ca: sslCa }),
              ...(sslCert && { cert: sslCert }),
              ...(sslKey && { key: sslKey }),
            };
          }
          // If no certificates, SSL remains false (connection will use non-SSL)
        }
        
        // Allow explicit SSL override via environment variable
        if (process.env.DB_USE_SSL === 'true' && process.env.DB_SSL_CA) {
          sslConfig = {
            rejectUnauthorized: true,
            ca: process.env.DB_SSL_CA,
            ...(process.env.DB_SSL_CERT && { cert: process.env.DB_SSL_CERT }),
            ...(process.env.DB_SSL_KEY && { key: process.env.DB_SSL_KEY }),
          };
        }

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
          migrations: postgresConfigService.migrations,
          entities: [
            'dist/**/*.entity.js',
            'dist/authentication/entities/*.entity.js',
            'dist/models/**/entities/*.entity.js',
          ],
          ssl: sslConfig,
        };
      },
      inject: [PostgresConfigService],
    } as TypeOrmModuleAsyncOptions),
  ],
})
export class PostgresDatabaseProviderModule {}