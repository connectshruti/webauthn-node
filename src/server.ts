import 'dotenv/config';
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRouter from './routes/userRoutes.js';
import passkeyRouter from './routes/passkeyRoutes.js';
import connectDB from "./config/db.js";
const app = express();
const port = process.env.PORT || 3000;
//Connect to MongoDB
connectDB();
// Middleware
app.use(cors({ credentials: true,
     origin: `${process.env.REACT_APP_FRONTEND}`,
       methods: "GET,POST,PUT,DELETE" })); // Adjust for frontend
app.use(express.json()); // Allows JSON request bodies
app.use(cookieParser(process.env.COOKIE_SECRET || '38374283472377y2euhwe8wrudhfdfsalfd')); // Allows reading cookies

app.use('/api/user', userRouter);
app.use('/api/passkey', passkeyRouter);

app.listen(port, () => console.log(`🚀 Server running at ${port}`));