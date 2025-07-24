import crypto from "crypto";
import User from "../models/userModel.js";
import sendToken from "../utils/jwtToken.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import ForgotPasswordEmail from "../utils/forgotPasswordEmail.js";
import sendEmail from "../utils/sendEmail.js";
import verifyEmail from '../utils/verifyEmail.js';

// User Registration
export const register = catchAsyncErrors(async (req, res, next) => {
  const { email, phone } = req.body;

  // Check if user already exists
  const userExist = await User.findOne({ email });
  if (userExist) {
    return next(new Errorhandler("Email already registered", 400));
  }

  // Check if user phone already exists
  const userPhoneExist = await User.findOne({ phone });
  if (userPhoneExist) {
    return next(new Errorhandler("Phone already registered", 400));
  }

  try {
    // Create a new user
    const user = await User.create(req.body);

    // Send token (login the user)
    sendToken(user, 200, res);
  } catch (error) {
    // Handle any other errors
    return next(
      new Errorhandler("Failed to create account. Please try again.", 500)
    );
  }
});

// user login
export const login = catchAsyncErrors(async (req, res, next) => {
  const { email, password } = req.body;

  // Use regex to check if input is email or phone
  const isEmail = email.includes("@"); 

  // Find user by email or phone
  const user = await User.findOne(
    isEmail ? { email } : { phone: email }
  ).select("+password");

  if (!user) {
    return next(new Errorhandler("Invalid email/phone or password", 401));
  }

  const isPasswordMatched = await user.comparePassword(password);
  if (!isPasswordMatched) {
    return next(new Errorhandler("Invalid email/phone or password", 401));
  }

  sendToken(user, 200, res);
});

// Logout User
export const logout = catchAsyncErrors(async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });

  res.status(200).json({
    success: true,
    message: "Logged out successfully",
  });
});

// // user profile (Get User Details)
export const profileDetails = catchAsyncErrors(async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return next(new Errorhandler("User not found!", 404));
    }
    res.status(200).json({
      success: true,
      user,
      message: "User info fetched successfully",
    });
  } catch (error) {
    next(error);
  }
});

// user profile update
export const profileUpdate = catchAsyncErrors(async (req, res, next) => {
  let user = await User.findByIdAndUpdate(req.user.id, req.body, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });
  if (!user) {
    user = await User.findByIdAndUpdate(req.user.id, req.body, {
      new: true,
      runValidators: true,
      useFindAndModify: false,
    });
  }
  res.status(200).json({
    success: true,
    user,
  });
});

// user profile update password
export const profileUpdatePassword = async (req, res, next) => {
  const user = await User.findById(req.user.id).select("+password");

  const isPasswordMatched = await user.comparePassword(req.body.oldPassword);
  if (!isPasswordMatched) {
    return next(new Errorhandler("Old password is incorrect", 400));
  }

  if (req.body.newPassword !== req.body.confirmPassword) {
    return next(new Errorhandler("Password does not match", 400));
  }
  user.password = req.body.newPassword;
  await user.save();
  sendToken(user, 200, res, Errorhandler);
};

// User Forgot Password
export const forgotPassword = catchAsyncErrors(async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    return next(new Errorhandler("Please Enter Your Email", 400));
  }

  let user = await User.findOne({ email });

  if (!user) {
    return next(new Errorhandler("User not found", 404));
  }

  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Hash the OTP to store securely
  const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

  // Save both OTP and its hashed version (hashed for token, plain for check)
  user.resetPasswordOtp = otp; 
  user.resetPasswordToken = hashedOtp;
  user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // expires in 10 min

  await user.save({ validateBeforeSave: false });

  // Email template
  const currentYear = new Date().getFullYear();
  const userName = user?.name;
  const html = ForgotPasswordEmail(otp, currentYear, userName);

  try {
    await sendEmail({
      email: user.email,
      subject: "Your OTP for Password Reset",
      html,
    });

    res.status(200).json({
      success: true,
      message: `OTP sent to ${user.email}. Please check your email.`,
      resetPasswordToken: user.resetPasswordToken
    });
  } catch (error) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    user.resetPasswordOtp = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new Errorhandler(error.message, 500));
  }
});

// Reset Password OTP Verification
export const resetPasswordverifyOtp = catchAsyncErrors(async (req, res, next) => {
  const { email, otp } = req.body;

  const user = await User.findOne({
    email,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user || user.resetPasswordOtp !== otp) {
    return next(new Errorhandler("Invalid or expired OTP", 400));
  }

  // Generate a new secure token (different from OTP)
  const rawResetToken = crypto.randomBytes(32).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(rawResetToken).digest("hex");

  user.resetPasswordToken = hashedToken;
  user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 mins more
  user.resetPasswordOtp = undefined; // remove OTP after verification
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    success: true,
    message: "OTP verified successfully",
    resetPasswordToken: rawResetToken, //  return raw token to frontend
  });
});

// Reset Password (confirm password)
export const resetPassword = catchAsyncErrors(async (req, res, next) => {
  try {
    const { password, confirmPassword, token } = req.body;

    if (!token) {
      return next(new Errorhandler("Token is required", 400));
    }

    // Hash the token received in the body
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    console.log("Token from body:", token);
    console.log("Hashed token:", resetPasswordToken);

    // Find user by hashed token and check expiry
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return next(
        new Errorhandler("Reset Password Token is invalid or has expired", 400)
      );
    }

    if (password !== confirmPassword) {
      return next(new Errorhandler("Passwords do not match", 400));
    }

    // Update password and clear reset fields
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    // Optionally log in user or just respond with success
    sendToken(user, 200, res); // If you're using JWT auth
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// Verify Email
const generateOTP = () => Math.floor(100000 + Math.random() * 900000);
export const sendEmailVerify = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const otp = generateOTP();
    const currentYear = new Date().getFullYear();

    // Update user or create if doesn't exist
    const user = await User.findOneAndUpdate(
      { email },
      {
        emailOtp:otp,
        emailOtpExpiry: Date.now() + 10 * 60 * 1000,
      },
      { new: true, upsert: true }
    );
    const userName = user.name || "User"; 
    const html = verifyEmail(otp, currentYear, userName || "User");

    await sendEmail({
      email,
      subject: "Verify Your Email - OTP Inside",
      html,
    });

    res.status(200).json({
      success: true,
      message: `OTP sent to ${email}. Please check your inbox.`,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Something went wrong while sending the OTP.',
    });
  }
};

// Email Verification OTP
export const emailVerifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required',
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const numericOtp = parseInt(otp);
    if (isNaN(numericOtp)) {
      return res.status(400).json({
        success: false,
        message: 'OTP must be a number',
      });
    }

    // Check OTP match
    if (user.emailOtp !== numericOtp) {
      return res.status(400).json({
        success: false,
        message: 'Incorrect OTP',
      });
    }

    // Check expiry
    if (!user.emailOtpExpiry || user.emailOtpExpiry < Date.now()) {
      return res.status(400).json({
        success: false,
        message: 'OTP has expired',
      });
    }

    // Mark as verified and clear OTP
    user.emailVerified = true;
    user.emailOtp = null;
    user.emailOtpExpiry = null;

    await user.save();

    return res.status(200).json({
      success: true,
      message: 'Email verified successfully',
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error',
    });
  }
};


// Get all users (Admin)
export const getAllUsers = catchAsyncErrors(async (req, res, next) => {
  const users = await User.find({ role: { $ne: 1 } }).select("-password").sort({ createdAt: -1 });

  if (!users || users.length === 0) {
    return next(new Errorhandler("No users found", 404));
  }

  res.status(200).json({
    success: true,
    users,
    message: "Users fetched successfully",
  });
});


// Delete user (Admin)
export const deleteUser = catchAsyncErrors(async (req, res, next) => {
  try {
    const deleteUser = await User.findByIdAndDelete(req.params.id);
    console.log("Delete User:", deleteUser);
  if (!deleteUser) {
    return next(new Errorhandler("User not found", 404))
  }
  res.status(200).json({
    success:true,
    deleteUser,
    message:"User deleted successfully"
  })
  } catch (error) {
    return next(new Errorhandler(error.message, 500))
  }
})




