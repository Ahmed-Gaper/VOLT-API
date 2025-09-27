import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config.js';
export interface AuthRequest extends Request {
  userId?: string;
  isGuest?: boolean;
}

export interface JwtPayload {
  id: string;
  email?: string;
  isGuest?: boolean;
  iat?: number;
  exp?: number;
}

export const authMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.',
      });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET!) as JwtPayload;

    if (decoded.isGuest) {
      req.isGuest = true;
      req.userId = decoded.id;
    } else {
      req.userId = decoded.id;
    }

    next();
  } catch (error) {
    console.log(`Internal server error: ${error}`);
    res.status(401).json({
      success: false,
      message: 'Invalid token',
    });
  }
};

export const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.isGuest) {
    return res.status(403).json({
      success: false,
      message: 'This action requires a registered account',
    });
  }
  next();
};
