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
  EMAIL_HOST: string;
  EMAIL_PORT: string;
  EMAIL_USERNAME: string;
  EMAIL_PASSWORD: string;
}

export const config: Config = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  DB_NAME: process.env.DB_NAME!,
  DATABASE_URL: `${process.env.DATABASE_URL!.split('?')[0]}${
    process.env.DB_NAME
  }?${process.env.DATABASE_URL!.split('?')[1]}`,
  JWT_SECRET: process.env.JWT_SECRET || 'default-jwt-secret',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN! as ms.StringValue,
  EMAIL_HOST: process.env.EMAIL_HOST!,
  EMAIL_PORT: process.env.EMAIL_PORT!,
  EMAIL_USERNAME: process.env.EMAIL_USERNAME!,
  EMAIL_PASSWORD: process.env.EMAIL_PASSWORD!,
};
