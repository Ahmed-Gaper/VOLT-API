import express from 'express';
import type { Application, Request, Response } from 'express';
import { config } from './config/config.js';
import connectDB from './config/database.js';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import { authRoutes } from './routes/authRoutes.js';
import './config/passport.js';

const app: Application = express();

if (config.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

// Routes
app.get('/api/health', (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: 'App API is running!',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/auth', authRoutes);

export default app;
