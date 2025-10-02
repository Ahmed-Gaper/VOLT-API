import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import ms from 'ms';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({
  path: path.resolve(__dirname, '../../config.env'),
});

export interface Config {
  PORT: number;
  NODE_ENV: string;
  DATABASE_URL: string;
  DB_NAME: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: ms.StringValue;
  JWT_REFRESH_SECRET: string;
  JWT_REFRESH_EXPIRES_IN: ms.StringValue;
  JWT_COOKIE_EXPIRES_IN: number;
  EMAIL_HOST: string;
  EMAIL_PORT: string;
  EMAIL_USERNAME: string;
  EMAIL_PASSWORD: string;
  // OAuth Configuration
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  FACEBOOK_APP_ID: string;
  FACEBOOK_APP_SECRET: string;
  APPLE_CLIENT_ID: string;
  APPLE_TEAM_ID: string;
  APPLE_KEY_ID: string;
  APPLE_PRIVATE_KEY: string;
}

export const config: Config = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  DB_NAME: process.env.DB_NAME!,
  DATABASE_URL: `${process.env.DATABASE_URL!.split('?')[0]}${process.env.DB_NAME}?${process.env.DATABASE_URL!.split('?')[1]}`,
  JWT_SECRET: process.env.JWT_SECRET || 'default-jwt-secret',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN! as ms.StringValue,
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'default-refresh-secret',
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN! as ms.StringValue,
  JWT_COOKIE_EXPIRES_IN: parseInt(process.env.JWT_COOKIE_EXPIRES_IN || '90', 10),
  EMAIL_HOST: process.env.EMAIL_HOST!,
  EMAIL_PORT: process.env.EMAIL_PORT!,
  EMAIL_USERNAME: process.env.EMAIL_USERNAME!,
  EMAIL_PASSWORD: process.env.EMAIL_PASSWORD!,
  // OAuth Configuration
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID!,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET!,
  FACEBOOK_APP_ID: process.env.FACEBOOK_APP_ID!,
  FACEBOOK_APP_SECRET: process.env.FACEBOOK_APP_SECRET!,
  APPLE_CLIENT_ID: process.env.APPLE_CLIENT_ID!,
  APPLE_TEAM_ID: process.env.APPLE_TEAM_ID!,
  APPLE_KEY_ID: process.env.APPLE_KEY_ID!,
  APPLE_PRIVATE_KEY: process.env.APPLE_PRIVATE_KEY!,
};
