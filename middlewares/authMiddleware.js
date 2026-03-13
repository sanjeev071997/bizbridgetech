import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "./catchAsyncErrors.js";
import jwt from 'jsonwebtoken'
import User from "../models/userModel.js";
import dotenv from "dotenv";
dotenv.config();

// authenticated user
export const isAuthenticatedUser = catchAsyncErrors(async (req, res, next) => {
  let token = req.cookies.token || req.cookies.refreshToken || (req.headers.authorization && req.headers.authorization.split(" ")[1]);

  if (!token) {
    return next(new Errorhandler("You must Log In...", 400));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return next(new Errorhandler("User not found", 404));
    req.user = user;
    next();
  } catch (err) {
    return next(new Errorhandler("Session expired. Please refresh token.", 401));
  }
});


// Admin 
export const isAdmin = catchAsyncErrors (async(req, res, next) => {
    if (req.user.role != 1) { // not equal admin
      return next(new Errorhandler('Access denied, you must an Only Admin', 403));
    }
    next();
});