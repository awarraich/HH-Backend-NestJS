import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';
import { migrations } from './src/database/migrations/index.js';

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
  migrations: ['dist/src/database/migrations/[0-9]*.js'],
  entities: [
    'dist/src/**/*.entity.js',
    'dist/src/authentication/entities/*.entity.js',
    'dist/src/models/**/entities/*.entity.js',
  ],
});
