import type { Response } from 'express';
import Block from '../models/block.js';
import { User } from '../models/user.js';
import { Follow } from '../models/follow.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';

interface PopulatedUser {
  _id: string;
  username: string;
  displayName: string;
  profilePicture: string[];
}

const badRequest = (res: Response, msg = 'Bad request') =>
  res.status(400).json({ success: false, message: msg });

export class BlockController {
  // POST /v1/users/:userId/block -- block target (caller blocks target)
  static async blockUser(req: AuthRequest, res: Response) {
    try {
      const callerId = req.userId; // logged-in user
      const targetId = req.params.userId;

      if (String(callerId) === String(targetId)) {
        return badRequest(res, "You can't block yourself");
      }

      const target = await User.findById(targetId).select('_id').lean();
      if (!target) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const upsertResult = await Block.updateOne(
        { blocker: callerId, blocked: targetId },
        { $setOnInsert: { createdAt: new Date() } }, // Only set on insert (not update)
        { upsert: true } // Create if doesn't exist
      );

      const created = !!(upsertResult.upsertedCount && upsertResult.upsertedCount > 0);

      // When blocking: remove follow relations in both directions
      // 1) caller -> target
      const removed1 = await Follow.findOneAndDelete({
        follower: callerId,
        followee: targetId,
      }).lean();
      if (removed1 && removed1.status === 'accepted') {
        // decrement counts
        await Promise.all([
          User.updateOne({ _id: targetId }, { $inc: { followersCount: -1 } }),
          User.updateOne({ _id: callerId }, { $inc: { followingCount: -1 } }),
        ]);
      }

      // 2) target -> caller
      const removed2 = await Follow.findOneAndDelete({
        follower: targetId,
        followee: callerId,
      }).lean();
      if (removed2 && removed2.status === 'accepted') {
        await Promise.all([
          User.updateOne({ _id: callerId }, { $inc: { followersCount: -1 } }),
          User.updateOne({ _id: targetId }, { $inc: { followingCount: -1 } }),
        ]);
      }

      if (created) {
        res.status(201).json({
          success: true,
          message: 'Block created successfully',
          data: {
            blocker: callerId,
            blocked: targetId,
            createdAt: new Date().toISOString(),
          },
        });
      } else {
        // already blocked
        res.status(200).json({
          success: true,
          message: 'Already blocked',
          data: {
            blocker: callerId,
            blocked: targetId,
          },
        });
      }
    } catch (err: unknown) {
      console.error('blockUser error', err);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async unblockUser(req: AuthRequest, res: Response) {
    try {
      const callerId = req.userId; // logged-in user
      const targetId = req.params.userId;

      const target = await User.findById(targetId).select('_id').lean();
      if (!target) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }
      await Block.findOneAndDelete({ blocker: callerId, blocked: targetId }).lean();

      res.status(200).json({
        success: true,
        message: 'Unblocked successfully',
        data: {
          blocker: callerId,
          blocked: targetId,
          status: 'unblocked',
        },
      });
    } catch (err: unknown) {
      console.error('unblockUser  error', err);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getBlocked(req: AuthRequest, res: Response) {
    const userId = req.userId;

    const page = parseInt(String(req.query.page || '1'), 10); // Current page (default: 1)
    const limit = parseInt(String(req.query.limit || '50'), 10); // Items per page (default: 50)
    const skip = (page - 1) * limit; // Calculate how many to skip

    const totalBlocked = await Block.find({ blocker: userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit) // pagination advised: add skip/limit via query params
      .populate({ path: 'blocked', select: 'username displayName profilePicture' })
      .lean();

    // Get total count for pagination info
    const total = await Block.countDocuments({
      blocker: userId,
    });

    // map output
    const result = totalBlocked.map((b) => ({
      id: b.blocked._id,
      username: (b.blocked as unknown as PopulatedUser).username,
      displayName: (b.blocked as unknown as PopulatedUser).displayName,
      profilePicture: (b.blocked as unknown as PopulatedUser).profilePicture,
      isLive: false,
    }));
    return res.status(200).json({
      success: true,
      message: 'Blocked users retrieved successfully',
      data: {
        results: result,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalResults: total,
          hasNextPage: page < Math.ceil(total / limit),
          hasPrevPage: page > 1,
        },
      },
    });
  }
}
