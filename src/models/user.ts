import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import ms from 'ms';
import { config } from '../config/config.js';
import { Query } from 'mongoose';

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
  passwordResetToken?: string;
  passwordResetExpires?: Date | undefined;
  refreshToken?: string;
  refreshTokenExpires?: Date;
  active: boolean;
  passwordChangedAt?: Date;

  comparePassword(candidatePassword: string): Promise<boolean>;
  createPasswordResetToken(): string;
  createRefreshToken(): string;
  isRefreshTokenValid(token: string): boolean;
}

const userSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      select: false,
      required(this: IUser) {
        return this.authProvider === 'local';
      },
    },
    displayName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },
    country: {
      type: String,
    },
    dateOfBirth: {
      type: Date,
    },
    bio: {
      type: String,
      maxlength: 500,
    },
    profilePicture: {
      type: String,
    },
    authProvider: {
      type: String,
      enum: ['local', 'google', 'facebook', 'apple'],
      default: 'local',
    },
    socialId: {
      type: String,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    role: {
      type: String,
      enum: ['viewer', 'streamer', 'admin'],
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
    passwordResetToken: String,
    passwordResetExpires: { type: Date, required: false },
    refreshToken: String,
    refreshTokenExpires: Date,
    passwordChangedAt: Date,
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
  (this as Query<Record<string, unknown>, IUser>).find({ active: true });
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  if (!this.password) {
    return false;
  }
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.createPasswordResetToken = function (): string {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; //current time + 10 minutes in milliseconds

  return resetToken;
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

export const User = model<IUser>('User', userSchema);
