// This middleware ensures that only authenticated users can access protected routes. Here's a breakdown of its functionality:

// ✅ Functionality:
// Extracts Token: Retrieves the token from cookies or the Authorization header.
// Validates Token:
// If missing, returns a 401 Unauthorized response.
// Verifies the token using jwt.verify().
// If invalid, returns a 401 Unauthorized response.
// Fetches User:
// Retrieves the user from the database using the decoded token's _id.
// If the user does not exist, returns a 401 Unauthorized response.
// Attaches User ID to Request:
// Converts the user's _id to a string and attaches it to req._id.
// Calls next() to proceed to the next middleware or controller.
import {Request, Response, NextFunction} from "express";
import jwt from "jsonwebtoken";
import {User} from "../models/user.model.js";
import {AuthRequest} from "../types/auth.js";

// interface AuthRequest extends Request {
//     user?: string | JwtPayload; // Extend Request type
// }
export const isAuthenticated=async(req:AuthRequest, res:Response, next:NextFunction)=>{
    try{
        const authHeader = req.headers.authorization;
        
        let token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;

        // Only fallback to cookies if Authorization header is missing
        if (!token) {
            token = req.cookies?.token || null;
        }
    if(!token){
        res.status(401).json({success:false, message:"Unauthorized: No token provided"});
        return;
        }
        //Verify the JWT token
        const decoded=jwt.verify(token, process.env.JWT_SECRET!)as{_id: string};
        if(!decoded||!decoded._id){
             res.status(401).json({success:false, message:"Unauthorized: Invalid token" });
             return;
        }

        //fetching the user from database
        const user=await User.findById(decoded._id);

        if(!user){
            res.status(401).json({success:false, message:"Unauthorized: User not found"});
            return;
        }

        //Attach the user id to the request object
        req._id=(user._id as any).toString();
         next();
         return;
    }catch(error){
        console.error("Error in isAuthenticated Middleware: ",error);
       res.status(401).json({success:false, message:"Unauthorized: Invalid or expired token"});
       return ;
    }
}