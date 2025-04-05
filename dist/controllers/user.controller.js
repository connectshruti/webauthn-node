// /This controller handles user authentication and profile management, including registration, login, logout, and retrieving user details.
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
// Register User
export const registerUser = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(400).json({ success: false, message: "User already exists" });
            return;
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const user = await User.create({ username, email, password: hashedPassword });
        res.status(201).json({ success: true, message: "User registered successfully" });
        return;
    }
    catch (error) {
        console.error("Error in registerUser: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
// Login User
export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            res.status(404).json({ success: false, message: "User not found" });
            return;
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(400).json({ success: false, message: "Invalid credentials" });
            return;
        }
        // Generate JWT Token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
        // Set token in HTTP-Only Cookie
        res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', path: "/" });
        res.status(200).json({
            success: true,
            message: "Login successful",
            user: {
                id: user._id,
                name: user.username,
                email: user.email,
            },
        });
        return;
    }
    catch (error) {
        console.error("Error in loginUser: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
// Logout User
export const logoutUser = async (req, res) => {
    try {
        res.clearCookie("token", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', path: "/" });
        res.status(200).json({ success: true, message: "Logout successful" });
        return;
    }
    catch (error) {
        console.error("Error in logoutUser: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
// Get User Profile (Protected Route)
export const getUserProfile = async (req, res) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            res.status(401).json({ success: false, message: "Unauthorized" });
            return;
        }
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded._id).select("-password"); // Exclude password
        if (!user) {
            res.status(404).json({ success: false, message: "User not found" });
            return;
        }
        res.status(200).json({ success: true, user });
        return;
    }
    catch (error) {
        console.error("Error in getUserProfile: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
