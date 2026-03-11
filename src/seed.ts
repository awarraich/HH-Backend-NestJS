import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { UserSeederService } from './database/seeders/users/seeder.service';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.createApplicationContext(AppModule);

  const userSeeder = app.get(UserSeederService);
  await userSeeder.seed();

  await app.close();
}

void bootstrap();
