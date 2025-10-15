import mongoose, { Document, Schema, Types, Model } from 'mongoose';

export interface IBlock extends Document {
  blocker: Types.ObjectId;
  blocked: Types.ObjectId;
  createdAt: Date;
}

const BlockSchema = new Schema<IBlock>(
  {
    blocker: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    blocked: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: () => new Date() },
  },
  { versionKey: false }
);

// prevent duplicates (same blocker -> blocked)
BlockSchema.index({ blocker: 1, blocked: 1 }, { unique: true });

const Block: Model<IBlock> = mongoose.models.Block || mongoose.model<IBlock>('Block', BlockSchema);
export default Block;
