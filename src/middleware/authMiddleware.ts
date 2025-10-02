import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config.js';
import { User } from '../models/user.js';

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

    // 3) Check if the user still exist
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      throw new Error('The user belonging to this token is no longer exist.');
    }

    // 4) Check if the user changed password after the token was issued
    if (decoded.iat !== undefined && (await currentUser.passwordChangedAfter(decoded.iat))) {
      throw new Error('User recently changed password! Please log in again');
    }

    next();
  } catch (error) {
    console.log(`Internal server error: ${error}`);
    res.status(401).json({
      success: false,
      message: 'Invalid token', // TO DO
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
