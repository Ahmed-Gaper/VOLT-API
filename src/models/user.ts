import { Schema, model, Document } from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
export interface IUser extends Document {
  username: string;
  email: string;
  password?: string; // Optional because social login users won't have it
  displayName: string;
  country?: string;
  dateOfBirth?: Date;
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

  comparePassword(candidatePassword: string): Promise<boolean>;
  createPasswordResetToken(): string;
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
    passwordResetToken: String,
    passwordResetExpires: { type: Date, required: false },
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

export const User = model<IUser>('User', userSchema);
