import mongoose from 'mongoose';
import { config } from './config.js';

const connectDB = async (): Promise<void> => {
  try {
    mongoose
      .connect(config.DATABASE_URL)
      .then(() => console.log(`✅ DB connection successful: ${config.DB_NAME}`));
  } catch (error) {
    console.error('❌ Database connection error:', error);
    process.exit(1);
  }
};

export default connectDB;
