import mongoose, { Schema, Document, Model } from 'mongoose';

export type FollowStatus = 'accepted' | 'requested';

export interface IFollow extends Document {
  follower: mongoose.Types.ObjectId; // who follows (actor)
  followee: mongoose.Types.ObjectId; // who is being followed (target)
  status: FollowStatus;
  createdAt: Date;
  updatedAt?: Date;
}

const followSchema = new Schema<IFollow>(
  {
    follower: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    followee: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    status: { type: String, required: true, enum: ['accepted', 'requested'], default: 'accepted' },
    createdAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true, // createdAt & updatedAt
  }
);

followSchema.index({ follower: 1, followee: 1 }, { unique: true });

export const Follow: Model<IFollow> = mongoose.model<IFollow>('follow', followSchema);
