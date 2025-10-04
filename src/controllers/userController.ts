import type { Response } from 'express';
import { User } from '../models/user.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';

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

  static async uploadProfilePicture(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      // Handle profile picture upload
      let profilePicturePath: string | undefined;
      if (req.file) {
        const s3File = req.file as Express.Multer.File & { location?: string };
        // S3 storage sets location property to the public URL
        profilePicturePath = s3File.location;
      } else {
        return res.status(400).json({
          success: false,
          message: 'Profile picture is required',
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      user.profilePicture = profilePicturePath ?? '';
      await user.save();

      res.json({
        success: true,
        message: 'Profile picture uploaded successfully',
        data: {
          user: {
            id: user._id,
            profilePicture: user.profilePicture,
          },
        },
      });
    } catch (error) {
      console.error('Upload profile picture error:', error);
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
}
