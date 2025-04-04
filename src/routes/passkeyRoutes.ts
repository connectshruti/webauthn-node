// This file defines API routes for handling passkey-based authentication using Express.js. The routes are:

// POST /register → Registers a passkey for an authenticated user.

// POST /verify → Verifies the registered passkey.

// POST /login-passkey → Initiates login using a passkey.

// POST /verify-passkey → Completes the login process by verifying the passkey.
import express from "express";
import { isAuthenticated } from "../middlewares/auth.js";
import { loginWithPasskey, registerPasskey, verifyPasskey, verifyWithPasskey } from "../controllers/passkey.controller.js";

const passkeyRouter = express.Router();
passkeyRouter.post("/register-passkey", isAuthenticated, registerPasskey);
passkeyRouter.post("/verify-register", isAuthenticated, verifyPasskey);
passkeyRouter.post("/login-passkey", loginWithPasskey); // No auth required
passkeyRouter.post("/verify-login", verifyWithPasskey); // No auth required

export default passkeyRouter;