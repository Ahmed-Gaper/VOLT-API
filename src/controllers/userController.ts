import type { Response } from 'express';
import { User, type IUser } from '../models/user.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';
import { Follow } from '../models/follow.js';
import mongoose, { type FilterQuery } from 'mongoose';
import Block from '../models/block.js';
import { sendEmail } from '../utils/email.js';
// helper: escape regex
function escapeRegex(text: string) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

interface ISearchResult {
  id: mongoose.Types.ObjectId;
  username: string;
  displayName: string;
  profilePicture?: string[] | undefined;
  isLive: boolean;
}

interface ISearchResponse {
  success: boolean;
  message: string;
  data: {
    results: ISearchResult[];
    pagination?: {
      currentPage: number;
      totalPages: number;
      totalResults: number;
      hasNextPage: boolean;
      hasPrevPage: boolean;
    };
  };
}
export class UserController {
  static async getProfile(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      // Fetch user
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      res.json({
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          user,
        },
      });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
  static async updateProfile(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;
      const { displayName, username, email, dateOfBirth, country, bio } = req.body;

      // Fetch user
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (typeof username === 'string') {
        // Can't be empty string
        user.username = username.trim();
      }
      if (typeof email === 'string') {
        // Can't be empty string
        user.email = email.trim();
      }

      if (typeof displayName === 'string') {
        user.displayName = displayName.trim() || user.username;
      }

      if (typeof country === 'string') {
        user.country = country.trim();
      }
      if (dateOfBirth !== undefined) {
        user.dateOfBirth = dateOfBirth ? new Date(dateOfBirth) : undefined;
      }

      if (typeof bio === 'string') {
        user.bio = bio.trim();
      }

      await user.save();

      res.json({
        success: true,
        message: 'Profile information updated successfully',
        data: {
          user: {
            username: user.username,
            email: user.email,
            displayName: user.displayName,
            ...(user.country && { country: user.country }),
            ...(user.dateOfBirth && { dateOfBirth: user.dateOfBirth }),
            ...(user.bio && { bio: user.bio }),
          },
        },
      });
    } catch (error) {
      console.error('Update profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async uploadProfilePictures(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      let profilePicturesPaths: string[] = [];
      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const s3Files = req.files as (Express.Multer.File & { location?: string })[];
        profilePicturesPaths = s3Files.map((file) => file.location ?? '').filter(Boolean);
      } else {
        return res.status(400).json({
          success: false,
          message: 'At least one profile picture is required',
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      user.profilePicture = profilePicturesPaths;
      await user.save();

      res.json({
        success: true,
        message: 'Profile pictures uploaded successfully',
        data: {
          user: {
            id: user._id,
            profilePicture: user.profilePicture,
          },
        },
      });
    } catch (error) {
      console.error('Upload profile pictures error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
  static async uploadProfilePosts(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      let profilePostsPaths: string[] = [];
      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const s3Files = req.files as (Express.Multer.File & { location?: string })[];
        profilePostsPaths = s3Files.map((file) => file.location ?? '').filter(Boolean);
      } else {
        return res.status(400).json({
          success: false,
          message: 'At least one profile post is required',
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (!user.profilePosts) {
        user.profilePosts = [];
      }
      user.profilePosts.push(...profilePostsPaths);
      user.postsCount = user.profilePosts.length;
      await user.save();

      res.status(201).json({
        success: true,
        message: 'Profile posts uploaded successfully',
        data: {
          user: {
            id: user._id,
            profilePosts: user.profilePosts,
            postsCount: user.postsCount,
          },
        },
      });
    } catch (error) {
      console.error('Upload profile posts error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async deletePost(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;
      const postId = req.params.postId;

      if (!postId) {
        return res.status(400).json({
          success: false,
          message: 'Post ID is required',
        });
      }

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const initialPostCount = user.profilePosts?.length ?? 0;
      if (user.profilePosts) {
        user.profilePosts = user.profilePosts.filter((post) => post !== postId);
      }

      if ((user.profilePosts?.length ?? 0) === initialPostCount) {
        return res.status(404).json({
          success: false,
          message: 'Post not found',
        });
      }

      user.postsCount = user.profilePosts?.length ?? 0;
      await user.save();

      res.status(200).json({
        success: true,
        message: 'Post deleted successfully',
      });
    } catch (error) {
      console.error('Delete profile post error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getPosts(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;
      const page = parseInt(String(req.query.page || '1'), 10);
      const limit = parseInt(String(req.query.limit || '50'), 10);

      const user = await User.findById(userId).select('profilePosts').lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const posts = user.profilePosts || [];
      const total = posts.length;
      const skip = (page - 1) * limit;
      const paginatedPosts = posts.slice(skip, skip + limit);

      return res.status(200).json({
        success: true,
        message: 'Posts retrieved successfully',
        data: {
          results: paginatedPosts,
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
      console.error('Get posts error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async deleteProfile(req: AuthRequest, res: Response) {
    try {
      await User.findByIdAndDelete(req.userId);
      res.status(204).json({
        success: true,
        message: 'Profile deleted successfully',
        data: null,
      });
    } catch (error) {
      console.error('Delete profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
  /**
   * GET /v1/users/search?q=...&limit=20&page=1&withCount=false&excludeBlocked=true
   */
  static async getUserProfile(req: AuthRequest, res: Response) {
    try {
      const { userId } = req.params;

      // Validate userId format
      if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid user ID',
        });
      }

      // Find the target user
      const targetUser = await User.findById(userId).select(
        'username displayName bio country profilePicture followersCount followingCount privateAccount postsCount createdAt'
      );

      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      // Determine if the requester follows the target user
      let isFollowing = false;
      if (req.userId && String(req.userId) !== String(userId)) {
        const follow = await Follow.findOne({
          follower: req.userId,
          followee: userId,
          status: 'accepted',
        }).lean();
        isFollowing = Boolean(follow);
      }

      // Return public profile information
      res.status(200).json({
        success: true,
        message: 'Profile retrieved successfully',
        data: {
          user: {
            id: targetUser._id,
            username: targetUser.username,
            displayName: targetUser.displayName,
            bio: targetUser.bio,
            country: targetUser.country,
            profilePicture: targetUser.profilePicture,
            followersCount: targetUser.followersCount,
            followingCount: targetUser.followingCount,
            postsCount: targetUser.postsCount,
            isFollowing,
            isLive: false,
            privateAccount: targetUser.privateAccount,
            createdAt: targetUser.createdAt,
          },
        },
      });
    } catch (error) {
      console.error('Get user profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async search(req: AuthRequest, res: Response) {
    try {
      const rawQ = (req.query.q as string) || '';
      const q = rawQ.trim();
      if (!q) {
        return res.status(400).json({ success: false, message: 'q (query) parameter is required' });
      }
      const maxLength = 50;
      if (q.length > maxLength) {
        return res.status(400).json({ success: false, message: 'Query too long' });
      }
      const limit = Math.min(Number(req.query.limit) || 20, 100);
      const page = Math.max(Number(req.query.page) || 1, 1);
      const withCount = req.query.withCount === 'true';
      const excludeBlocked = req.query.excludeBlocked !== 'false'; // default true

      // Build safe regex for partial, case-insensitive match
      const safe = escapeRegex(q);
      const regex = new RegExp(safe, 'i');

      // Base query: match username OR name
      const baseQuery: FilterQuery<IUser> = {
        $or: [{ username: regex }, { displayName: regex }],
      };

      // Optionally exclude blocked users if caller is authenticated and excludeBlocked=true
      let finalQuery: FilterQuery<IUser> = baseQuery;
      if (excludeBlocked && req.userId) {
        const callerId = req.userId;
        // find blocks in either direction (caller blocked target OR target blocked caller)
        const blocks = await Block.find({
          $or: [{ blocker: callerId }, { blocked: callerId }],
        })
          .select('blocker blocked')
          .lean();

        const excludeSet = new Set<string>();
        for (const b of blocks) {
          // if caller blocked someone -> exclude that blocked user from results
          if (String(b.blocker) === String(callerId)) {
            excludeSet.add(String(b.blocked));
          }
          // if someone blocked caller -> exclude that blocker from results
          if (String(b.blocked) === String(callerId)) {
            excludeSet.add(String(b.blocker));
          }
        }

        if (excludeSet.size > 0) {
          finalQuery = {
            $and: [
              baseQuery,
              {
                _id: { $nin: Array.from(excludeSet).map((id) => new mongoose.Types.ObjectId(id)) },
              },
            ],
          };
        }
      }

      const projection = {
        username: 1,
        displayName: 1,
        profilePicture: 1,
      };

      const skip = (page - 1) * limit;

      // Execute main query
      const docsPromise = User.find(finalQuery)
        .select(projection)
        .sort({ username: 1 })
        .skip(skip)
        .limit(limit)
        .lean();

      // Optionally fetch total count (expensive at scale)
      const countPromise = withCount ? User.countDocuments(finalQuery) : Promise.resolve(null);

      const [docs, total] = await Promise.all([docsPromise, countPromise]);

      const data: ISearchResult[] = (docs || []).map((u) => ({
        id: u._id as mongoose.Types.ObjectId,
        username: u.username,
        displayName: u.displayName,
        profilePicture: u.profilePicture,
        isLive: false,
      }));

      const responseData: ISearchResponse['data'] = {
        results: data,
      };

      if (withCount && total !== null) {
        const totalResults = total;
        const totalPages = Math.ceil(totalResults / limit);
        const hasNextPage = page < totalPages;
        const hasPrevPage = page > 1;

        responseData.pagination = {
          currentPage: page,
          totalPages,
          totalResults,
          hasNextPage,
          hasPrevPage,
        };
      }

      const response: ISearchResponse = {
        success: true,
        message: 'Search successful',
        data: responseData,
      };

      return res.status(200).json(response);
    } catch (err: unknown) {
      console.error('search error', err);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async contactSupport(req: AuthRequest, res: Response) {
    try {
      const { name, email, message } = req.body;

      // Validation
      if (!name || !email || !message) {
        return res.status(400).json({
          success: false,
          message: 'Name, email, and message are required',
        });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message: 'Please provide a valid email address',
        });
      }

      // Validate message length
      if (message.trim().length < 10) {
        return res.status(400).json({
          success: false,
          message: 'Message must be at least 10 characters long',
        });
      }

      if (message.trim().length > 1000) {
        return res.status(400).json({
          success: false,
          message: 'Message must be less than 1000 characters',
        });
      }

      // Create support email content
      const supportEmailContent = `
New Support Request from ${name}

Email: ${email}
User ID: ${req.userId || 'Not authenticated (public contact form)'}

Message:
${message.trim()}

---
This message was sent via the Volt app support system.
      `.trim();

      // Send email to support team
      await sendEmail({
        email: 'support@volts.com',
        subject: `Support Request from ${name}`,
        message: supportEmailContent,
      });

      // Send confirmation email to user
      const userConfirmationContent = `
Hello ${name},

Thank you for contacting Volt support. We have received your message and will get back to you as soon as possible.

Your message:
${message.trim()}

Best regards,
Volt Support Team
      `.trim();

      await sendEmail({
        email,
        subject: 'Support Request Received - Volt',
        message: userConfirmationContent,
      });

      res.status(200).json({
        success: true,
        message:
          'Support request submitted successfully. You will receive a confirmation email shortly.',
      });
    } catch (error) {
      console.error('Contact support error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getUserPosts(req: AuthRequest, res: Response) {
    try {
      const targetId = req.params.userId;

      const page = parseInt(String(req.query.page || '1'), 10);
      const limit = parseInt(String(req.query.limit || '50'), 10);

      const user = await User.findById(targetId).select('profilePosts').lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const posts = user.profilePosts || [];
      const total = posts.length;
      const skip = (page - 1) * limit;
      const paginatedPosts = posts.slice(skip, skip + limit);

      return res.status(200).json({
        success: true,
        message: 'Posts retrieved successfully',
        data: {
          results: paginatedPosts,
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
      console.error('Get user posts error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
}
