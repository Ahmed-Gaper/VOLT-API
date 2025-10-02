import express from 'express';
import type { Application, Request, Response } from 'express';
import { config } from './config/config.js';
import connectDB from './config/database.js';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mongoSanitize from '@exortek/express-mongo-sanitize';
import { xss } from 'express-xss-sanitizer';
import hpp from 'hpp';
import { authRoutes } from './routes/authRoutes.js';
import { userRoutes } from './routes/userRoutes.js';
import './config/passport.js';

const app: Application = express();

// Connect to database
connectDB();

// Security middleware
app.use(helmet()); // Set security-related HTTP headers

if (config.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
});
app.use('/api/auth', limiter);

// General middleware
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

// Security middleware
app.use(mongoSanitize.default());
app.use(xss()); // Prevent Cross-Site Scripting (XSS) attacks
app.use(hpp()); // Protect against HTTP Parameter Pollution attacks

// Health check route
app.get('/api/health', (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: 'App API is running!',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

export default app;
