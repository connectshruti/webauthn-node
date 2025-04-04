// Challenge Model: Stores WebAuthn challenges for user authentication, expiring after 5 minutes.

import mongoose, { Schema, Document } from 'mongoose';
import { User } from './user.model.js';

interface IChallenge extends Document {
    userId: mongoose.Schema.Types.ObjectId;
    payload: string;
    createdAt: Date;
}

const ChallengeSchema = new Schema<IChallenge>({
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    payload: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 }, // Auto-delete after 300 seconds
});

export const Challenge = mongoose.model<IChallenge>("Challenge", ChallengeSchema);
