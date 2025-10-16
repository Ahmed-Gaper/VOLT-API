// middleware/authMiddleware.ts
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
        message: 'Access denied: No authorization token provided.',
      });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET!) as JwtPayload;

    if (decoded.isGuest) {
      req.isGuest = true;
      req.userId = decoded.id;
    } else {
      req.userId = decoded.id;
    }

    // Check user existence
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token: User associated with token does not exist.',
      });
    }

    // Check if user changed password after token issuance
    if (decoded.iat !== undefined && (await currentUser.passwordChangedAfter(decoded.iat))) {
      return res.status(401).json({
        success: false,
        message: 'Access denied: User password recently changed, please log in again.',
      });
    }

    return next();
  } catch (error) {
    console.log(`authMiddleware error: ${error}`);
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token.',
      });
    }
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    });
  }
};

export const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.isGuest) {
    return res.status(403).json({
      success: false,
      message: 'This action requires a registered user account.',
    });
  }
  next();
};
