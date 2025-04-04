// This file sets up routes for user authentication and profile management in an Express app. The defined routes are:

// POST /registeruser → Registers a new user.

// POST /loginuser → Logs in an existing user.

// POST /logout → Logs out the user by clearing the token.

// GET /userprofile → Fetches the authenticated user's profile (protected by isAuthenticated).

import express from "express";
import { registerUser, loginUser, logoutUser, getUserProfile } from "../controllers/user.controller.js";
import { isAuthenticated } from "../middlewares/auth.js";

const userRouter = express.Router();
userRouter.post("/register", registerUser);
userRouter.post("/login", loginUser);
userRouter.post("/logout", isAuthenticated, logoutUser);
userRouter.get("/profile",isAuthenticated, getUserProfile);

export default userRouter;