import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "./catchAsyncErrors.js";
import jwt from 'jsonwebtoken'
import User from "../models/userModel.js";
import dotenv from "dotenv";
dotenv.config();

// authenticated user
export const isAuthenticatedUser = catchAsyncErrors(async (req, res, next) => {
    const authHeader = req.cookies.token  || req.headers['authorization'];
    const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);
    
    if (!token) {
        return next(new Errorhandler("You must Log In...", 400));
    }

    const decodedData = jwt.verify(token, process.env.JWT_SECRET);

    // Attempt to find the user in the User model
    let user = await User.findById(decodedData?.id);

    if (!user) {
        return next(new Errorhandler("User not found", 404));
    }
    
    req.user = user;
    next();
});

// Admin 
export const isAdmin = catchAsyncErrors (async(req, res, next) => {
    if (req.user.role != 1) { // not equal admin
      return next(new Errorhandler('Access denied, you must an Only Admin', 403));
    }
    next();
});