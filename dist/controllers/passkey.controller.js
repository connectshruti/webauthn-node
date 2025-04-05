// This controller handles WebAuthn-based passkey authentication for users, including registration, verification, login, and authentication validation.
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { Passkey } from "../models/passkey.model.js";
import { Challenge } from "../models/challenge.model.js";
import { generateRegistrationOptions, verifyRegistrationResponse, verifyAuthenticationResponse, generateAuthenticationOptions, } from "@simplewebauthn/server";
import { isoUint8Array, isoBase64URL } from "@simplewebauthn/server/helpers";
// Utility function to check required environment variables
const checkEnvVariables = () => {
    const requiredVars = ["RP_NAME", "RP_ID", "ORIGIN", "NODE_ENV", "JWT_SECRET"];
    requiredVars.forEach((key) => {
        if (!process.env[key]) {
            throw new Error(`Missing required environment variable: ${key}`);
        }
    });
};
// Generate JWT Token
const generateToken = (userId) => {
    return jwt.sign({ _id: userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
};
// 1. Registration Passkey Endpoint-This endpoint generates a WebAuthn registration challenge for a user who wants to register a passkey. 
export const registerPasskey = async (req, res) => {
    try {
        checkEnvVariables();
        const userId = req._id;
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, message: "User not found" });
            return;
        }
        const userPasskeys = await Passkey.find({ userId });
        const options = await generateRegistrationOptions({
            rpName: process.env.RP_NAME,
            rpID: process.env.RP_ID,
            userID: isoUint8Array.fromUTF8String(userId),
            userName: user.username,
            excludeCredentials: userPasskeys.map((passkey) => ({
                id: isoBase64URL.fromBuffer(passkey.credentialID),
                transports: passkey.transports,
            })),
            authenticatorSelection: {
                userVerification: "required", // ✅ This replaces `requireUserVerification`
            },
            timeout: 300000,
        });
        await Challenge.create({ userId, payload: options.challenge, createdAt: new Date() });
        res.status(200).json({ success: true, message: "Passkey registration options generated", options });
        return;
    }
    catch (error) {
        console.error("Error in registerPasskey: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
// 2. Verification Passkey Endpoint-This endpoint verifies the WebAuthn registration response sent by the client.
export const verifyPasskey = async (req, res) => {
    try {
        checkEnvVariables();
        const { credential } = req.body;
        const userId = req._id;
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, message: "User not found" });
            return;
        }
        const challenge = await Challenge.findOne({ userId }).sort({ createdAt: -1 });
        if (!challenge) {
            res.status(400).json({ success: false, message: "Challenge not found" });
            return;
        }
        if (Date.now() - new Date(challenge.createdAt).getTime() > 5 * 60 * 1000) {
            res.status(400).json({ success: false, message: "Challenge expired" });
            return;
        }
        const verificationResult = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: challenge.payload,
            expectedOrigin: process.env.ORIGIN,
            expectedRPID: process.env.RP_ID,
        });
        if (!verificationResult.verified) {
            res.status(400).json({ success: false, message: "Passkey verification failed" });
            return;
        }
        // ✅ Extract registration info properly
        const registrationInfo = verificationResult.registrationInfo;
        if (!registrationInfo.credential) {
            res.status(400).json({ success: false, message: "Credential data missing" });
            return;
        }
        // ✅ Extract passkey data safely
        const credentialID = registrationInfo.credential.id;
        const credentialPublicKey = registrationInfo.credential.publicKey;
        const counter = registrationInfo.credential.counter;
        const transports = registrationInfo.credential.transports ?? [];
        if (!credential) {
            res.status(400).json({ success: false, message: "Credential data missing" });
            return;
        }
        if (!credentialID || !credentialPublicKey) {
            res.status(400).json({ success: false, message: "Invalid registration data" });
            return;
        }
        const passkey = await Passkey.create({
            userId,
            credentialID: Buffer.from(credentialID),
            publicKey: Buffer.from(credentialPublicKey),
            counter,
            transports,
        });
        await Challenge.deleteMany({ userId });
        user.passkeys = user.passkeys || [];
        user.passkeys.push(passkey.id);
        await user.save();
        res.status(200).json({ success: true, message: "Passkey registered successfully" });
        return;
    }
    catch (error) {
        console.error("Error in verifyPasskey: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
// 3. login with passkey- This function generates authentication options for a user who wants to log in using a passkey.
export const loginWithPasskey = async (req, res) => {
    try {
        checkEnvVariables();
        const { email } = req.body; // ✅ Get email from request    
        if (!email) {
            res.status(400).json({ success: false, message: "Email is required" });
            return;
        }
        const user = await User.findOne({ email });
        if (!user) {
            res.status(404).json({ success: false, message: "User not found" });
            return;
        }
        const userPasskeys = await Passkey.find({ userId: user._id });
        if (userPasskeys.length === 0) {
            res.status(400).json({ success: false, message: "No registered passkeys found" });
            return;
        }
        const options = await generateAuthenticationOptions({
            rpID: process.env.RP_ID,
            allowCredentials: userPasskeys.map((passkey) => ({
                id: isoBase64URL.fromBuffer(passkey.credentialID),
                transports: passkey.transports,
            })),
            timeout: 300000,
        });
        await Challenge.create({ userId: user._id, payload: options.challenge });
        res.status(200).json({ success: true, message: "Passkey login options generated", options });
        return;
    }
    catch (error) {
        console.error("Error in loginWithPasskey: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
// 4. verify with passkey
export const verifyWithPasskey = async (req, res) => {
    try {
        checkEnvVariables();
        const { credential } = req.body;
        const userId = req._id;
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, message: "User not found" });
            return;
        }
        const challenge = await Challenge.findOne({ userId }).sort({ createdAt: -1 });
        if (!challenge) {
            res.status(400).json({ success: false, message: "Challenge not found" });
            return;
        }
        const passkey = await Passkey.findOne({ userId });
        if (!passkey || isoBase64URL.fromBuffer(passkey.credentialID) !== credential.id) {
            res.status(400).json({ success: false, message: "Passkey not found" });
            return;
        }
        const verificationResult = await verifyAuthenticationResponse({
            expectedChallenge: challenge.payload,
            expectedOrigin: process.env.ORIGIN,
            expectedRPID: process.env.RP_ID,
            response: credential,
            credential: {
                id: isoBase64URL.fromBuffer(passkey.credentialID),
                publicKey: new Uint8Array(Buffer.from(passkey.publicKey).buffer),
                counter: passkey.counter,
                transports: passkey.transports,
            },
        });
        if (!verificationResult.verified) {
            res.status(400).json({ success: false, message: "Authentication failed" });
            return;
        }
        if (verificationResult.authenticationInfo?.newCounter && verificationResult.authenticationInfo.newCounter <= passkey.counter) {
            res.status(400).json({ success: false, message: "Counter replay detected" });
            return;
        }
        passkey.counter = verificationResult.authenticationInfo.newCounter;
        await passkey.save();
        await Challenge.deleteMany({ userId });
        const token = generateToken(userId);
        res.cookie("token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', path: "/" });
        res.status(200).json({ success: true, message: "Login successful", token });
        return;
    }
    catch (error) {
        console.error("Error in verifyWithPasskey: ", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
        return;
    }
};
