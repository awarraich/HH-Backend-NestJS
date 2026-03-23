import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PostgresConfigService {
  constructor(private configService: ConfigService) {}

  get type(): string {
    return this.configService.get<string>('database.type', 'postgres');
  }

  get host(): string {
    return this.configService.get<string>('database.host', 'localhost');
  }

  get port(): number {
    return this.configService.get<number>('database.port', 5432);
  }

  get username(): string {
    return this.configService.get<string>('database.username', 'postgres');
  }

  get password(): string {
    return this.configService.get<string>('database.password', '');
  }

  get database(): string {
    return this.configService.get<string>('database.database', 'hh_backend');
  }

  get synchronize(): boolean {
    return this.configService.get<boolean>('database.synchronize', false);
  }

  get logging(): boolean {
    return this.configService.get<boolean>('database.logging', false);
  }

  get migrationsRun(): boolean {
    return this.configService.get<boolean>('database.migrationsRun', false);
  }

  get migrations(): string[] {
    return this.configService.get<string[]>('database.migrations', [
      'dist/src/database/migrations/*.js',
    ]);
  }
}
