import 'dotenv/config';
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRouter from './src/routes/userRoutes';
import passkeyRouter from './src/routes/passkeyRoutes';
import connectDB from "./src/config/db.js";
const app = express();
const port = process.env.PORT || 3000;
//Connect to MongoDB
connectDB();
// Middleware
app.use(cors({ credentials: true, origin: `${process.env.REACT_APP_FRONTEND}`,  methods: "GET,POST,PUT,DELETE" })); // Adjust for frontend
app.use(express.json()); // Allows JSON request bodies
app.use(cookieParser()); // Allows reading cookies

app.use('/api/user', userRouter);
app.use('/api/passkey', passkeyRouter);

app.listen(port, () => console.log(`🚀 Server running at ${port}`));