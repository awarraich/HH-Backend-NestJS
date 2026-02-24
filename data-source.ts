import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';

dotenv.config({
  path: process.env.NODE_ENV === 'production' 
    ? '.env.production' 
    : process.env.NODE_ENV === 'development' 
      ? '.env.development' 
      : '.env',
});

export default new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'home_health_ai',
  migrations: ['dist/database/migrations/*.js'],
  entities: [
    'dist/**/*.entity.js',
    'dist/authentication/entities/*.entity.js',
    'dist/models/**/entities/*.entity.js',
  ],
});
