import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import ms from 'ms';
import { config } from '../config/config.js';
import { Query } from 'mongoose';
import validator from 'validator';

export interface IUser extends Document {
  username: string;
  email: string;
  password?: string; // Optional because social login users won't have it
  displayName: string;
  country?: string;
  dateOfBirth?: Date | undefined;
  bio?: string;
  profilePicture?: string;
  authProvider: 'local' | 'google' | 'facebook' | 'apple';
  socialId?: string;
  isVerified: boolean;
  role: 'viewer' | 'streamer' | 'admin';
  followers: Schema.Types.ObjectId[];
  following: Schema.Types.ObjectId[];
  createdAt: Date;
  updatedAt: Date;
  refreshToken?: string;
  refreshTokenExpires?: Date;
  active: boolean;
  passwordChangedAt?: Date;
  passwordResetOtp?: string;
  passwordResetOtpExpires?: Date | undefined;
  passwordResetOtpAttempts?: number;
  passwordResetOtpLockedUntil?: Date | undefined;
  emailVerificationOtp?: string;
  emailVerificationOtpExpires?: Date | undefined;
  emailVerificationOtpAttempts?: number;
  emailVerificationOtpLockedUntil?: Date | undefined;

  comparePassword(candidatePassword: string): Promise<boolean>;
  createPasswordResetOtp(): string;
  createRefreshToken(): string;
  isRefreshTokenValid(token: string): boolean;
  createEmailVerificationOtp(): string;
  passwordChangedAfter(JWTTimestamp: number): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters long'],
      maxlength: [30, 'Username cannot exceed 30 characters'],
      match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      trim: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email'],
    },
    password: {
      type: String,
      select: false,
      required(this: IUser) {
        return this.authProvider === 'local';
      },
      minlength: [8, 'Password must be at least 8 characters long'],
      validate: [
        validator.isStrongPassword,
        'Password must be at least 8 characters and include a lowercase letter, an uppercase letter, a number, and a symbol.',
      ],
    },
    displayName: {
      type: String,
      required: [true, 'Display name is required'],
      trim: true,
      minlength: [1, 'Display name cannot be empty'],
      maxlength: [50, 'Display name cannot exceed 50 characters'],
    },
    country: {
      type: String,
    },
    dateOfBirth: {
      type: Date,
      validate: {
        validator(dob: Date) {
          if (!dob) {
            return true;
          }

          const minAge = 13;
          const maxAge = 120;
          const today = new Date();
          const age = today.getFullYear() - dob.getFullYear();

          return age >= minAge && age <= maxAge;
        },
        message: 'You must be at least 13 years old to use this platform',
      },
    },
    bio: {
      type: String,
      maxlength: [500, 'Bio cannot exceed 500 characters'],
    },
    profilePicture: {
      type: String,
    },
    authProvider: {
      type: String,
      enum: {
        values: ['local', 'google', 'facebook', 'apple'],
        message: 'Auth provider must be one of: local, google, facebook, apple',
      },
      default: 'local',
    },
    socialId: {
      type: String,
      validate: {
        validator(socialId: string) {
          // Social ID is required for social auth, not for local
          if (this.authProvider === 'local') {
            return true;
          }
          return !!socialId && socialId.length > 0;
        },
        message: 'Social ID is required for social authentication',
      },
    },
    role: {
      type: String,
      enum: {
        values: ['viewer', 'streamer', 'admin'],
        message: 'Role must be one of: viewer, streamer, admin',
      },
      default: 'viewer',
    },
    followers: [
      {
        type: Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    following: [
      {
        type: Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    active: {
      type: Boolean,
      default: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    passwordResetOtp: String,
    passwordResetOtpExpires: { type: Date, required: false },
    passwordResetOtpAttempts: { type: Number, default: 0 },
    passwordResetOtpLockedUntil: { type: Date, required: false },
    refreshToken: String,
    refreshTokenExpires: Date,
    passwordChangedAt: Date,
    emailVerificationOtp: String,
    emailVerificationOtpExpires: { type: Date, required: false },
    emailVerificationOtpAttempts: { type: Number, default: 0 },
    emailVerificationOtpLockedUntil: { type: Date, required: false },
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error as Error);
  }
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) {
    return next();
  }

  this.passwordChangedAt = new Date(Date.now() - 1000); //abstract one second
  return next();
});

userSchema.pre(/^find/, function (next) {
  (this as Query<Record<string, unknown>, IUser>).find({ active: { $ne: false } });
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  if (!this.password) {
    return false;
  }
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.createRefreshToken = function (): string {
  const refreshToken = jwt.sign({ id: this._id, email: this.email }, config.JWT_REFRESH_SECRET, {
    expiresIn: config.JWT_REFRESH_EXPIRES_IN,
  });

  this.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
  this.refreshTokenExpires = new Date(Date.now() + ms(config.JWT_REFRESH_EXPIRES_IN));

  return refreshToken;
};

userSchema.methods.isRefreshTokenValid = function (token: string): boolean {
  if (!this.refreshToken || !this.refreshTokenExpires) {
    return false;
  }

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  return this.refreshToken === hashedToken && this.refreshTokenExpires > Date.now();
};

userSchema.methods.createEmailVerificationOtp = function (): string {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  this.emailVerificationOtp = crypto.createHash('sha256').update(otp).digest('hex');
  this.emailVerificationOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
  return otp;
};

userSchema.methods.createPasswordResetOtp = function (): string {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  this.passwordResetOtp = crypto.createHash('sha256').update(otp).digest('hex');
  this.passwordResetOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
  return otp;
};

userSchema.methods.passwordChangedAfter = async function (JWTTimestamp: number) {
  if (this.passwordChangedAt) {
    const changedTimestamp = this.passwordChangedAt.getTime() / 1000;
    // console.log(JWTTimestamp, changedTimestamp);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

export const User = model<IUser>('User', userSchema);
