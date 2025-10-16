// middleware/blockCheck.ts
import type { Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import Block from '../models/block.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';

export async function blockCheck(req: AuthRequest, res: Response, next: NextFunction) {
  try {
    const callerId = req.userId; // logged-in user
    const targetId = req.params.userId;

    if (!targetId || !mongoose.Types.ObjectId.isValid(targetId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID parameter.',
      });
    }

    // Allow self actions without blocking
    if (String(callerId) === String(targetId)) {
      return next();
    }

    // Fetch blocks in either direction
    const blocks = await Block.find({
      $or: [
        { blocker: callerId, blocked: targetId },
        { blocker: targetId, blocked: callerId },
      ],
    }).lean();

    let callerBlockedTarget = false;
    let blockedByTarget = false;

    for (const b of blocks) {
      if (String(b.blocker) === String(callerId) && String(b.blocked) === String(targetId)) {
        callerBlockedTarget = true;
      }
      if (String(b.blocker) === String(targetId) && String(b.blocked) === String(callerId)) {
        blockedByTarget = true;
      }
    }

    if (blockedByTarget || callerBlockedTarget) {
      return res.status(403).json({
        success: false,
        message: blockedByTarget
          ? 'Action forbidden: You are blocked by the user.'
          : 'Action forbidden: You have blocked this user.',
      });
    }

    return next();
  } catch (error) {
    console.error('blockCheck middleware error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error.',
    });
  }
}
