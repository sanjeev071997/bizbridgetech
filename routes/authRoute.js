import express from "express";
import {
  register,
  login,
  refreshAccessToken,
  logout,
  profileDetails,
  profileUpdate,
  profileUpdatePassword,
  forgotPassword,
  resetPasswordverifyOtp,
  resetPassword,
  sendEmailVerify,
  emailVerifyOtp,
  getAllUsers,
  deleteUser,
  updateUserMode,
  sendOtpToPhone,
  verifyPhoneOtp,
} from "../controllers/authController.js";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";
import { registerValidation, loginValidation, profileUpdateValidation, profileUpdatePasswordValidation, resetPasswordValidation } from '../helpers/authHelper.js';

const router = express.Router();

router.post("/register",registerValidation, register);
router.post("/login",loginValidation, login);
router.get("/refresh", refreshAccessToken);
router.get("/logout", logout);
router.get("/profile", isAuthenticatedUser, profileDetails);
router.put("/profile/update", isAuthenticatedUser, profileUpdateValidation, profileUpdate);
router.put("/profile/password/update", isAuthenticatedUser, profileUpdatePasswordValidation, profileUpdatePassword ); // Change password
router.post("/password/forgot", forgotPassword);
router.post("/verify/otp", resetPasswordverifyOtp); // Reset password link
router.put("/password/reset", resetPasswordValidation, resetPassword);
router.post("/email/verify", sendEmailVerify); // Send Email verification
router.post("/email/verify/otp", emailVerifyOtp); // Verify Email OTP
router.post("/send/otp", isAuthenticatedUser, sendOtpToPhone); // Send OTP to phone number
router.post("/verify/phone/otp", isAuthenticatedUser, verifyPhoneOtp); // Verify phone OTP
router.patch("/update-mode/:id", isAuthenticatedUser, updateUserMode); // Update user mode (buyer/seller)
router.get("/admin/all/users",  isAuthenticatedUser,isAdmin, getAllUsers); // Get all users
router.delete("/admin/user/:id", isAuthenticatedUser, isAdmin, deleteUser); // Delete user

export default router;
