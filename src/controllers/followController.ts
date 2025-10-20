import type { Response } from 'express';
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
const notFound = (res: Response, msg = 'Not found') =>
  res.status(404).json({ success: false, message: msg });
const forbidden = (res: Response, msg = 'Forbidden') =>
  res.status(403).json({ success: false, message: msg });

export class FollowController {
  static async followUser(req: AuthRequest, res: Response) {
    try {
      const actorId = req.userId; // logged-in user
      const targetId = req.params.userId;

      if (actorId === targetId) {
        return badRequest(res, "You can't follow yourself");
      }

      // fetch target user
      const target = await User.findById(targetId).select('+blockedUsers +pendingFollowRequests');

      if (!target) {
        return notFound(res, 'Target user not found');
      }

      // check blocks (either direction)
      const blocked = false; //TO DO
      if (blocked) {
        return forbidden(res, 'Cannot follow due to block');
      }

      // check existing follow relation (actor -> target)
      const existing = await Follow.findOne({ follower: actorId, followee: targetId });

      if (existing) {
        return res.status(200).json({ success: true, message: 'Already following' });
      }

      // create follow
      const follow = new Follow({
        follower: actorId,
        followee: targetId,
        createdAt: new Date(),
      });
      await follow.save();

      // update counters
      await Promise.all([
        User.findByIdAndUpdate(actorId, { $inc: { followingCount: 1 } }),
        User.findByIdAndUpdate(targetId, { $inc: { followersCount: 1 } }),
      ]);

      res.status(201).json({
        success: true,
        message: `You are now following ${target.username}.`,
      });
    } catch (error) {
      console.error('Follow user error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async unfollowUser(req: AuthRequest, res: Response) {
    try {
      const actorId = req.userId;
      const targetId = req.params.userId;

      if (actorId === targetId) {
        return badRequest(res, "You can't unfollow yourself");
      }

      const existing = await Follow.findOne({ follower: actorId, followee: targetId });
      if (!existing) {
        return notFound(res, 'Follow relationship not found');
      }

      await Promise.all([
        User.findByIdAndUpdate(actorId, { $inc: { followingCount: -1 } }),
        User.findByIdAndUpdate(targetId, { $inc: { followersCount: -1 } }),
      ]);

      await existing.deleteOne();

      res.status(200).json({
        success: true,
        message: 'Unfollowed successfully',
      });
    } catch (error) {
      console.error('Unfollow user error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getFollowers(req: AuthRequest, res: Response) {
    try {
      const userId = req.params.userId;

      const page = parseInt(String(req.query.page || '1'), 10); // Current page (default: 1)
      const limit = parseInt(String(req.query.limit || '50'), 10); // Items per page (default: 50)
      const skip = (page - 1) * limit; // Calculate how many to skip
      const user = await User.findById(userId).lean(); // lean >> When you only need data, not methods
      if (!user) {
        return notFound(res);
      }

      // Only return minimal user info for each follower; populate as needed
      const followers = await Follow.find({ followee: userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit) // pagination advised: add skip/limit via query params
        .populate({ path: 'follower', select: 'username displayName profilePicture' })
        .lean();

      // Get total count for pagination info
      const total = await Follow.countDocuments({
        followee: userId,
      });

      // map output
      const result = followers.map((f) => ({
        id: f._id, // The follow relationship ID
        createdAt: f.createdAt, // When the follow was requested
        user: {
          id: f.follower._id,
          username: (f.follower as unknown as PopulatedUser).username,
          displayName: (f.follower as unknown as PopulatedUser).displayName,
          profilePicture: (f.follower as unknown as PopulatedUser).profilePicture,
        },
      }));
      return res.status(200).json({
        success: true,
        message: 'Followers retrieved successfully',
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
    } catch (error) {
      console.error('getFollowers  error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
  static async getFollowing(req: AuthRequest, res: Response) {
    try {
      const userId = req.params.userId;

      const page = parseInt(String(req.query.page || '1'), 10);
      const limit = parseInt(String(req.query.limit || '50'), 10);
      const skip = (page - 1) * limit;

      const user = await User.findById(userId).lean();
      if (!user) {
        return notFound(res);
      }

      const followers = await Follow.find({ follower: userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit) // pagination advised: add skip/limit via query params
        .populate({ path: 'followee', select: 'username displayName profilePicture' })
        .lean();

      const total = await Follow.countDocuments({ followee: userId });

      const result = followers.map((f) => ({
        id: f._id,
        createdAt: f.createdAt,
        user: {
          id: f.followee._id,
          username: (f.followee as unknown as PopulatedUser).username,
          displayName: (f.followee as unknown as PopulatedUser).displayName,
          profilePicture: (f.followee as unknown as PopulatedUser).profilePicture,
        },
      }));
      return res.status(200).json({
        success: true,
        message: 'Following retrieved successfully',
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
    } catch (error) {
      console.error('getFollowing  error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
}
