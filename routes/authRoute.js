import express from "express";
import multer from "multer";
import path from "path";
import {
  register,
  login,
  googleWithRegister,
  googleWithlogin,
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
  // sendOtpToPhone,
  // verifyPhoneOtp,
  uploadProfileImage,
  deleteProfileImage,
  sendOtp,
verifyOtp,
} from "../controllers/authController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";
import {
  registerValidation,
  loginValidation,
  profileUpdateValidation,
  profileUpdatePasswordValidation,
  resetPasswordValidation,
} from "../helpers/authHelper.js";

const router = express.Router();

const storage = multer.diskStorage({
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase(),
    );

    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  },
});

router.post("/register", registerValidation, register);
router.post("/login", loginValidation, login);
router.post("/google-register", googleWithRegister);
router.post("/google-login", googleWithlogin);
router.post("/refresh", refreshAccessToken);
router.get("/logout", logout);
router.get("/profile", isAuthenticatedUser, profileDetails);
router.put(
  "/profile/update",
  isAuthenticatedUser,
  profileUpdateValidation,
  profileUpdate,
);
router.put(
  "/profile/password/update",
  isAuthenticatedUser,
  profileUpdatePasswordValidation,
  profileUpdatePassword,
); // Change password
router.post("/password/forgot", forgotPassword);
router.post("/verify/otp", resetPasswordverifyOtp); // Reset password link
router.put("/password/reset", resetPasswordValidation, resetPassword);
router.post("/email/verify", sendEmailVerify); // Send Email verification
router.post("/email/verify/otp", emailVerifyOtp); // Verify Email OTP
// router.post("/send/otp", isAuthenticatedUser, sendOtpToPhone); // Send OTP to phone number
// router.post("/verify/phone/otp", isAuthenticatedUser, verifyPhoneOtp); // Verify phone OTP
router.patch("/update-mode/:id", isAuthenticatedUser, updateUserMode); // Update user mode (buyer/seller)
router.get("/admin/all/users", isAuthenticatedUser, isAdmin, getAllUsers); // Get all users
router.delete("/admin/user/:id", isAuthenticatedUser, isAdmin, deleteUser); // Delete user
router.put(
  "/profile/upload-image",
  isAuthenticatedUser,
  upload.single("profileImage"),
  uploadProfileImage,
);
// Delete profile image
router.delete("/profile/delete-image", isAuthenticatedUser, deleteProfileImage);

router.post("/send-otp", sendOtp);
router.post("/verify-otp", verifyOtp);

export default router;
