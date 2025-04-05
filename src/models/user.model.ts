// User Model: Defines users with authentication details and supports JWT token generation.

import mongoose, { Document } from 'mongoose';
import jwt from "jsonwebtoken";

export interface IUserDocument extends Document {
    username: string;
    email: string;
    password: string;
    twoFactorAuth?: boolean;
    passkeys?: mongoose.Schema.Types.ObjectId[];
    generateToken(): string; // JWT token generation method
}

const UserSchema = new mongoose.Schema<IUserDocument>({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true, match: [/^\S+@\S+\.\S+$/, "Invalid email format"] },
    password: { type: String, required: true },
    twoFactorAuth: { type: Boolean, default: false },
    passkeys: [{ type: mongoose.Schema.Types.ObjectId, ref: "Passkey" }]
}, { timestamps: true });

// Implementing the generateToken method
UserSchema.methods.generateToken = function (): string {
    return jwt.sign(
        { _id: this._id },
        process.env.JWT_SECRET as string, // Using JWT_SECRET from .env file
        { expiresIn: "7d" } // Token expires in 7 days
    );
};

export const User = mongoose.model<IUserDocument>("User", UserSchema);
