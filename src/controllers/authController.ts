import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';
import { config } from '../config/config.js';

export class AuthController {
  private static signToken(id: unknown, email: string): string {
    const token: string = jwt.sign({ id, email }, config.JWT_SECRET, {
      expiresIn: config.JWT_EXPIRES_IN,
    });
    return token;
  }

  static async signUp(req: Request, res: Response) {
    try {
      const { username, email, password, confirmPassword } = req.body;

      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match',
        });
      }

      const existingUser = await User.findOne({
        $or: [{ email }, { username }],
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User with this email or username already exists',
        });
      }

      const user = new User({
        username,
        email,
        password,
        displayName: username,
        country: '',
        dateOfBirth: new Date(),
        bio: '',
        onboardingStep: 1,
      });

      console.log(user);

      await user.save();

      const token: string = AuthController.signToken(user._id, user.email);

      res.status(201).json({
        success: true,
        message: 'Account created successfully. Please complete your profile.',
        data: {
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            onboardingStep: user.onboardingStep,
          },
        },
      });
    } catch (error) {
      console.error('Signup error:', error);
      let errorMessage = 'Internal server error';
      if (error instanceof Error) {
        errorMessage = `Internal server error: ${error.message}`;
      }
      res.status(500).json({
        success: false,
        message: errorMessage,
      });
    }
  }

  static async completeProfile(req: AuthRequest, res: Response) {
    try {
      const { displayName, dateOfBirth, country, bio } = req.body;
      const userId = req.userId;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      // Update user profile
      user.displayName = displayName;
      user.country = country;
      user.dateOfBirth = dateOfBirth && new Date(dateOfBirth);
      user.bio = bio;
      user.onboardingStep = 2;

      await user.save();

      res.json({
        success: true,
        message: 'Profile information updated successfully',
        data: {
          user: {
            id: user._id,
            displayName: user.displayName,
            onboardingStep: user.onboardingStep,
          },
        },
      });
    } catch (error) {
      console.error('Complete profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async uploadProfilePicture(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;
      const profilePicture = '';

      if (!profilePicture) {
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

      user.profilePicture = profilePicture;
      user.onboardingStep = 3; // Onboarding complete
      await user.save();

      res.json({
        success: true,
        message: 'Profile picture uploaded successfully',
        data: {
          user: {
            id: user._id,
            profilePicture: user.profilePicture,
            onboardingStep: user.onboardingStep,
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

  static async skipCompleteProfile(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      user.onboardingStep = 2;
      await user.save();

      res.json({
        success: true,
        message: 'Profile completion skipped.',
        data: {
          user: {
            id: user._id,
            onboardingStep: user.onboardingStep,
          },
        },
      });
    } catch (error) {
      console.error('Skip complete profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
  static async skipProfilePicture(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      user.onboardingStep = 3; // Onboarding complete
      await user.save();

      res.json({
        success: true,
        message: 'Profile setup completed successfully',
        data: {
          user: {
            id: user._id,
            onboardingStep: user.onboardingStep,
          },
        },
      });
    } catch (error) {
      console.error('Skip profile picture error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
}
