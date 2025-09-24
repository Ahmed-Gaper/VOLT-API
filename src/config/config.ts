import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

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
}

export const config: Config = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  DB_NAME: process.env.DB_NAME!,
  DATABASE_URL: `${process.env.DATABASE_URL!.split('?')[0]}${
    process.env.DB_NAME
  }?${process.env.DATABASE_URL!.split('?')[1]}`,
};
