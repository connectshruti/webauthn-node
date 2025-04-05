// User Model: Defines users with authentication details and supports JWT token generation.
import mongoose from 'mongoose';
import jwt from "jsonwebtoken";
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true, match: [/^\S+@\S+\.\S+$/, "Invalid email format"] },
    password: { type: String, required: true },
    twoFactorAuth: { type: Boolean, default: false },
    passkeys: [{ type: mongoose.Schema.Types.ObjectId, ref: "Passkey" }]
}, { timestamps: true });
// Implementing the generateToken method
UserSchema.methods.generateToken = function () {
    return jwt.sign({ _id: this._id }, process.env.JWT_SECRET, // Using JWT_SECRET from .env file
    { expiresIn: "7d" } // Token expires in 7 days
    );
};
export const User = mongoose.model("User", UserSchema);
