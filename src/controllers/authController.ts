import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';
import { config } from '../config/config.js';
import { sendEmail } from '../utils/email.js';
import crypto from 'crypto';

export class AuthController {
  private static signToken(id: unknown, email: string): string {
    const token: string = jwt.sign({ id, email }, config.JWT_SECRET, {
      expiresIn: config.JWT_EXPIRES_IN,
    });
    return token;
  }

  static async signUp(req: Request, res: Response) {
    try {
      const {
        username,
        email,
        password,
        confirmPassword,
        displayName,
        country,
        dateOfBirth,
        bio,
        profilePicture,
      } = req.body;

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
        displayName: displayName || username,
        ...(country?.trim() && { country }),
        ...(dateOfBirth && { dateOfBirth: new Date(dateOfBirth) }),
        ...(bio?.trim() && { bio }),
        ...(profilePicture?.trim() && { profilePicture }),
      });

      console.log(user);

      await user.save();

      const token: string = AuthController.signToken(user._id, user.email);

      res.status(201).json({
        success: true,
        message: 'Account created successfully.',
        data: {
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            displayName: user.displayName,
            ...(user.country && { country: user.country }),
            ...(user.dateOfBirth && { dateOfBirth: user.dateOfBirth }),
            ...(user.bio && { bio: user.bio }),
            ...(user.profilePicture && { profilePicture: user.profilePicture }),
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

  static async login(req: Request, res: Response) {
    try {
      const { identifier, password } = req.body;

      if (!identifier || !password) {
        return res.status(400).json({
          success: false,
          message: 'Identifier and password are required',
        });
      }

      const user = await User.findOne({
        $or: [{ email: identifier }, { username: identifier }],
      }).select('+password');

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
      }

      if (!user.password) {
        return res.status(401).json({
          success: false,
          message:
            'This account was created with social login. Please use the appropriate login method.',
        });
      }

      const isPasswordValid = await user.comparePassword(password);

      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
      }

      const token: string = AuthController.signToken(user._id, user.email);

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            displayName: user.displayName,
            ...(user.country && { country: user.country }),
            ...(user.dateOfBirth && { dateOfBirth: user.dateOfBirth }),
            ...(user.bio && { bio: user.bio }),
            ...(user.profilePicture && { profilePicture: user.profilePicture }),
            role: user.role,
            isVerified: user.isVerified,
          },
        },
      });
    } catch (error) {
      console.error('Login error:', error);
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

      await user.save();

      res.json({
        success: true,
        message: 'Profile information updated successfully',
        data: {
          user: {
            id: user._id,
            displayName: user.displayName,
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

  static async forgotPassword(req: Request, res: Response) {
    try {
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        // Don't reveal whether email exists or not
        return res.json({
          success: true,
          message: 'If an account with that email exists, a reset link has been sent',
        });
      }

      const resetToken: string = user.createPasswordResetToken();

      await user.save({ validateBeforeSave: false });

      const resetURL = `${req.protocol}://${req.get(
        'host'
      )}/api/v1/users/resetpassword/${resetToken}`;

      const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

      try {
        await sendEmail({
          email: req.body.email,
          subject: 'Your password reset token(valid for 10 minu)',
          message,
        });

        res.status(201).json({
          status: 'success',
          message: 'Token sent to email',
        });
      } catch (error) {
        user.passwordResetToken = '';
        user.passwordResetExpires = undefined;
        console.error('Sent token to email error:', error);

        res.status(404).json({
          status: 'fail',
          message: 'Internal server error',
        });
      }
    } catch (error) {
      console.error('Forgot password error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async resetPassword(req: Request, res: Response) {
    try {
      const { newPassword, confirmPassword } = req.body;

      if (newPassword !== confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match',
        });
      }

      if (!req.params.token) {
        return res.status(400).json({
          success: false,
          message: 'Reset token is required',
        });
      }

      const hashedToken = crypto
        .createHash('sha256')
        .update(req.params.token as string)
        .digest('hex');

      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Token is invalid or has expired',
        });
      }

      user.password = newPassword;
      user.passwordResetToken = '';
      user.passwordResetExpires = undefined;
      await user.save();

      res.json({
        success: true,
        message: 'Password reset successfully',
      });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({
        success: false,
        message: 'Invalid or expired reset token',
      });
    }
  }
}
