import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.js';
import type { AuthRequest } from '../middleware/authMiddleware.js';
import { config } from '../config/config.js';
import { sendEmail } from '../utils/email.js';
import crypto from 'crypto';
import { OAuthService } from '../services/oauthService.js';
import type { IUser } from '../models/user.js';

export class AuthController {
  private static signToken(id: IUser['_id'], email: string): string {
    return jwt.sign({ id, email }, config.JWT_SECRET, {
      expiresIn: config.JWT_EXPIRES_IN,
    });
  }

  private static getUserResponse(user: IUser) {
    return {
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
      ...(user.authProvider && { authProvider: user.authProvider }),
    };
  }

  private static async generateTokensAndSave(user: IUser) {
    const token = AuthController.signToken(user._id, user.email);
    const refreshToken = user.createRefreshToken();
    await user.save();
    return { token, refreshToken };
  }

  private static async sendAuthResponse(
    res: Response,
    user: IUser,
    options: { statusCode?: number; message?: string; includeUser?: boolean } = {}
  ) {
    const { statusCode = 200, message = 'Success', includeUser = true } = options;

    const { token, refreshToken } = await AuthController.generateTokensAndSave(user);

    const cookieOptions = {
      expires: new Date(Date.now() + config.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
      httpOnly: true,
    } as {
      expires: Date;
      httpOnly: boolean;
      secure?: boolean;
    };
    if (config.NODE_ENV === 'production') {
      cookieOptions.secure = true;
    }
    res.cookie('jwt', token, cookieOptions);

    const data: {
      token: string;
      refreshToken: string;
      user?: ReturnType<typeof AuthController.getUserResponse>;
    } = { token, refreshToken };

    if (includeUser) {
      data.user = AuthController.getUserResponse(user);
    }
    res.status(statusCode).json({
      success: true,
      message,
      data,
    });
  }

  // Social Authentication Methods
  static async googleLogin(req: Request, res: Response) {
    try {
      const { accessToken } = req.body;

      if (!accessToken) {
        return res.status(400).json({
          success: false,
          message: 'Access token is required',
        });
      }

      const socialData = await OAuthService.verifyGoogleToken(accessToken);
      if (!socialData) {
        return res.status(401).json({
          success: false,
          message: 'Invalid Google token',
        });
      }

      const { user, isNewUser } = await OAuthService.findOrCreateSocialUser(socialData);

      const statusCode = isNewUser ? 201 : 200;
      const message = isNewUser ? 'Account created successfully' : 'Login successful';
      await AuthController.sendAuthResponse(res, user, { statusCode, message });
    } catch (error) {
      console.error('Google login error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async facebookLogin(req: Request, res: Response) {
    try {
      const { accessToken } = req.body;

      if (!accessToken) {
        return res.status(400).json({
          success: false,
          message: 'Access token is required',
        });
      }

      const socialData = await OAuthService.verifyFacebookToken(accessToken);
      if (!socialData) {
        return res.status(401).json({
          success: false,
          message: 'Invalid Facebook token',
        });
      }

      const { user, isNewUser } = await OAuthService.findOrCreateSocialUser(socialData);

      const statusCode = isNewUser ? 201 : 200;
      const message = isNewUser ? 'Account created successfully' : 'Login successful';
      await AuthController.sendAuthResponse(res, user, { statusCode, message });
    } catch (error) {
      console.error('Facebook login error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async getOAuthUrls(req: Request, res: Response) {
    try {
      const urls = OAuthService.getOAuthUrls();
      res.status(200).json({
        success: true,
        data: urls,
      });
    } catch (error) {
      console.error('Get OAuth URLs error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
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

      await AuthController.sendAuthResponse(res, user, {
        statusCode: 201,
        message: 'Account created successfully',
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

      await AuthController.sendAuthResponse(res, user, { message: 'Login successful' });
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

      // OTP-only flow
      const otp: string = (
        user as unknown as { createPasswordResetOtp: () => string }
      ).createPasswordResetOtp();
      // Clear legacy token fields to avoid mixed flows
      user.passwordResetToken = '';
      user.passwordResetExpires = undefined;

      await user.save({ validateBeforeSave: false });

      const message =
        `Use this 6-digit OTP within 10 minutes: ${otp}\n` +
        `Then call POST /api/auth/verify-otp with { email, otp }.\n` +
        `On success, you'll receive a short-lived reset token to use with POST /api/auth/resetpassword (body: { token, newPassword, confirmPassword }).\n` +
        `If you didn't request this, ignore this email.`;

      try {
        await sendEmail({
          email: req.body.email,
          subject: 'Your password reset token (valid for 10 minutes)',
          message,
        });

        res.status(201).json({
          status: 'success',
          message: 'OTP sent to email',
        });
      } catch (error) {
        user.passwordResetOtp = '';
        user.passwordResetOtpExpires = undefined;
        console.error('Sent token to email error:', error);

        try {
          await user.save({ validateBeforeSave: false });
        } catch (saveError) {
          console.error('Failed to clear reset token after email error:', saveError);
        }

        res.status(500).json({
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
      // OTP-only flow expects a body token (short-lived) rather than URL token
      const { token, newPassword, confirmPassword } = req.body as {
        token?: string;
        newPassword?: string;
        confirmPassword?: string;
      };

      if (!token) {
        return res.status(400).json({
          success: false,
          message: 'Reset token is required',
        });
      }

      if (!newPassword || !confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'New password and confirm password are required',
        });
      }

      if (newPassword !== confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match',
        });
      }

      let payload: { id: string; email: string } | null = null;
      try {
        payload = jwt.verify(token, config.JWT_REFRESH_SECRET) as { id: string; email: string };
      } catch (_) {
        return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
      }

      const user = await User.findById(payload.id).select('+password');

      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token',
        });
      }

      user.password = newPassword;
      user.passwordResetOtp = '';
      user.passwordResetOtpExpires = undefined;
      await user.save();

      res.json({
        success: true,
        message: 'Password reset successfully',
      });
    } catch (error) {
      console.error('Reset password error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error', //TO DO
      });
    }
  }

  static async verifyOtp(req: Request, res: Response) {
    try {
      const { email, otp } = req.body as { email?: string; otp?: string };
      if (!email || !otp) {
        return res.status(400).json({ success: false, message: 'Email and OTP are required' });
      }

      // Check lock
      const normalizedEmail = String(email).trim().toLowerCase();
      const user = await User.findOne({ email: normalizedEmail });
      if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
      }

      if (user.passwordResetOtpLockedUntil && user.passwordResetOtpLockedUntil > new Date()) {
        return res
          .status(429)
          .json({ success: false, message: 'Too many attempts. Try again later.' });
      }

      if (!user.passwordResetOtp || !user.passwordResetOtpExpires) {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
      }

      const hashedOtp = crypto.createHash('sha256').update(String(otp)).digest('hex');
      const isValid =
        user.passwordResetOtp === hashedOtp && user.passwordResetOtpExpires > new Date();

      if (!isValid) {
        user.passwordResetOtpAttempts = (user.passwordResetOtpAttempts || 0) + 1;
        if (user.passwordResetOtpAttempts >= 5) {
          user.passwordResetOtpLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
          user.passwordResetOtpAttempts = 0;
        }
        await user.save({ validateBeforeSave: false });
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
      }

      // OTP valid, reset attempts and issue short-lived reset token (5 min)
      user.passwordResetOtpAttempts = 0;
      await user.save({ validateBeforeSave: false });
      const resetToken = jwt.sign({ id: user._id, email: user.email }, config.JWT_REFRESH_SECRET, {
        expiresIn: '5m',
      });
      return res.json({ success: true, data: { token: resetToken } });
    } catch (error) {
      console.error('Verify OTP error:', error);
      return res.status(500).json({ success: false, message: 'Internal server error' });
    }
  }

  static async refreshToken(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          message: 'Refresh token is required',
        });
      }

      const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as {
        id: string;
        email: string;
      };

      const user = await User.findById(decoded.id);
      if (!user || !user.isRefreshTokenValid(refreshToken)) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired refresh token',
        });
      }

      const newAccessToken = AuthController.signToken(user._id, user.email);
      const newRefreshToken = user.createRefreshToken();
      await user.save();

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          token: newAccessToken,
          refreshToken: newRefreshToken,
        },
      });
    } catch (error) {
      console.error('Refresh token error:', error);
      res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
      });
    }
  }

  static async logout(req: AuthRequest, res: Response) {
    try {
      const userId = req.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          message: 'User not authenticated',
        });
      }

      await User.findByIdAndUpdate(userId, {
        $unset: { refreshToken: 1, refreshTokenExpires: 1 },
      });

      res.status(200).json({
        success: true,
        message: 'Logged out successfully',
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async updatePassword(req: AuthRequest, res: Response) {
    try {
      const user = await User.findById(req.userId).select('+password');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const correct = await user.comparePassword(req.body.passwordCurrent);

      if (!correct) {
        return res.status(400).json({
          success: false,
          message: 'Your current password is wrong',
        });
      }
      if (req.body.password !== req.body.confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match',
        });
      }

      user.password = req.body.password;

      await AuthController.sendAuthResponse(res, user, {
        statusCode: 200,
        message: 'Password updated successfully',
      });
    } catch (error) {
      console.error('Update password error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
}
