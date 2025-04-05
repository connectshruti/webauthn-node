// Challenge Model: Stores WebAuthn challenges for user authentication, expiring after 5 minutes.
import mongoose, { Schema } from 'mongoose';
const ChallengeSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    payload: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 }, // Auto-delete after 300 seconds
});
export const Challenge = mongoose.model("Challenge", ChallengeSchema);
