// /This controller handles user authentication and profile management, including registration, login, logout, and retrieving user details.

// Register User (registerUser)
// Checks if the email is already registered.
// Hashes the password and creates a new user.
// Returns success response upon successful registration.

// Login User (loginUser)
// Verifies the user’s email and password.
// Generates a JWT token for authentication.
// Sets the token in an HTTP-only cookie for security.

// Logout User (logoutUser)
// Clears the authentication token cookie.
// Sends a success response confirming logout.

// Get User Profile (getUserProfile) (Protected Route)
// Fetches user details (excluding password) based on authenticated user ID.
// Returns the user’s profile information.

import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

// Register User
export const registerUser = async (req: Request, res: Response) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
             res.status(400).json({ success: false, message: "User already exists" });
             return
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const user = await User.create({ username, email, password: hashedPassword });

         res.status(201).json({ success: true, message: "User registered successfully" });
         return
    } catch (error) {
        console.error("Error in registerUser: ", error);
         res.status(500).json({ success: false, message: "Internal Server Error" });
         return
    }
};

// Login User
export const loginUser = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
             res.status(404).json({ success: false, message: "User not found" });
             return
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
             res.status(400).json({ success: false, message: "Invalid credentials" });
             return
        }

        // Generate JWT Token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET!, { expiresIn: "7d" });

        // Set token in HTTP-Only Cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV==="production", // Secure in production
            sameSite: "none",
            path:"/"
        });

         res.status(200).json({
            success: true,
            message: "Login successful",
            user: {
                id: user._id,
                name: user.username,
                email: user.email,
            },
        });
        return
    } catch (error) {
        console.error("Error in loginUser: ", error);
         res.status(500).json({ success: false, message: "Internal Server Error" });
         return
    }
};

// Logout User
export const logoutUser = async (req: Request, res: Response) => {
    try {
        res.clearCookie("token", { httpOnly: true,secure:process.env.NODE_ENV==="production", sameSite: "none",path:"/" });
         res.status(200).json({ success: true, message: "Logout successful" });
         return
    } catch (error) {
        console.error("Error in logoutUser: ", error);
         res.status(500).json({ success: false, message: "Internal Server Error" });
         return
    }
};

// Get User Profile (Protected Route)
export const getUserProfile = async (req: Request, res: Response) => {
    try {
        const token = req.cookies.token;
        if (!token) {
             res.status(401).json({ success: false, message: "Unauthorized" });
             return
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { _id: string };
        const user = await User.findById(decoded._id).select("-password"); // Exclude password

        if (!user) {
             res.status(404).json({ success: false, message: "User not found" });
             return
        }

         res.status(200).json({ success: true, user });
         return
    } catch (error) {
        console.error("Error in getUserProfile: ", error);
         res.status(500).json({ success: false, message: "Internal Server Error" });
         return
    }
};