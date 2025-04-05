// This middleware ensures that only authenticated users can access protected routes. Here's a breakdown of its functionality:
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
// interface AuthRequest extends Request {
//     user?: string | JwtPayload; // Extend Request type
// }
export const isAuthenticated = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        let token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;
        // Only fallback to cookies if Authorization header is missing
        if (!token) {
            token = req.cookies?.token || null;
        }
        if (!token) {
            res.status(401).json({ success: false, message: "Unauthorized: No token provided" });
            return;
        }
        //Verify the JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded || !decoded._id) {
            res.status(401).json({ success: false, message: "Unauthorized: Invalid token" });
            return;
        }
        //fetching the user from database
        const user = await User.findById(decoded._id);
        if (!user) {
            res.status(401).json({ success: false, message: "Unauthorized: User not found" });
            return;
        }
        //Attach the user id to the request object
        req._id = user._id.toString();
        next();
        return;
    }
    catch (error) {
        console.error("Error in isAuthenticated Middleware: ", error);
        res.status(401).json({ success: false, message: "Unauthorized: Invalid or expired token" });
        return;
    }
};
