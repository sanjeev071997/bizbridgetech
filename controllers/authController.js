import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";
import BuyerCategory from "../models/buyerCategoriesModel.js";
import PaymentOption from "../models/paymentOption.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import Otp from "../models/OTPModel.js";
import sendToken from "../utils/jwtToken.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import ForgotPasswordEmail from "../utils/forgotPasswordEmail.js";
import sendEmail from "../utils/sendEmail.js";
import verifyEmail from "../utils/verifyEmail.js";
// import { sendOtp } from "../utils/sendOtp.js";
import { generateOtp } from "../utils/generateOtp.js";
import { normalizeEmail } from "../utils/emailNormalizer.js";
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
import cloudinary from "../utils/cloudinary.js";
import axios from "axios";
import { sendOtpViaFast2SMS } from "../utils/fast2smsService.js";

const normalizePhone = (phone) => {
  if (!phone) return null;

  phone = phone.replace(/\s|-/g, "");

  if (phone.startsWith("+91")) return phone;
  if (phone.startsWith("91") && phone.length === 12) return `+${phone}`;
  if (phone.length === 10) return `+91${phone}`;

  return phone;
};

// // Send OTP API
// export const sendOtp = async (req, res) => {
//   try {
//     let { phone, email } = req.body;
//     phone = normalizePhone(phone);

//     if (!phone) {
//       return res.status(400).json({
//         success: false,
//         message: "Valid phone number required",
//       });
//     }

//     const otp = generateOtp();
//     const expiresAt = new Date(
//       Date.now() + Number(process.env.FAST2SMS_OTP_EXPIRE_MINUTES || 10) * 60 * 1000
//     );

//     // Delete old OTP
//     await Otp.deleteMany({ phone });

//     await Otp.create({ phone, email, otp, expiresAt });

//     // Send OTP via Fast2SMS
//     // await sendSmsOtpFast2SMS(phone, otp);

//     res.status(200).json({
//       success: true,
//       message: "OTP sent successfully via SMS",
//       otp: otp,
//     });
//   } catch (error) {
//     console.error("OTP Send Error:", error.response?.data || error);
//     res.status(500).json({
//       success: false,
//       message: "Failed to send OTP",
//     });
//   }
// };

// export const loginSendOtp = async (req, res) => {
//   try {
//     let { phone, email } = req.body;
//     console.log(phone, "phone")
//     // phone = normalizePhone(phone);

//     console.log(phone, "normalized phone");

//     if (!phone) {
//       return res.status(400).json({
//         success: false,
//         message: "Valid phone number required",
//       });
//     }

//     // 🔥 Check if user exists
//     const user = await User.findOne({ phone });

//     if (!user) {
//       return res.status(404).json({
//         success: false,
//         message: "User not registered with this phone number",
//       });
//     }

//     const otp = generateOtp();
//     const expiresAt = new Date(
//       Date.now() +
//         Number(process.env.FAST2SMS_OTP_EXPIRE_MINUTES || 10) *
//           60 *
//           1000
//     );

//     await Otp.deleteMany({ phone });
//     await Otp.create({ phone, email, otp, expiresAt });

//     res.status(200).json({
//       success: true,
//       message: "OTP sent successfully",
//       otp: otp, // remove in production
//     });

//   } catch (error) {
//     console.error("OTP Send Error:", error);
//     res.status(500).json({
//       success: false,
//       message: "Failed to send OTP",
//     });
//   }
// };

// login otp
export const loginSendOtp = async (req, res) => {
  try {
    let { phone, email } = req.body;

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: "Valid phone number required",
      });
    }
    // Optional: Validate phone number format (Indian numbers)
    const phoneRegex = /^[6-9]\d{9}$/; // 10-digit Indian mobile number
    const cleanPhone = phone.replace(/\D/g, ""); // Remove non-digits

    if (!phoneRegex.test(cleanPhone)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid 10-digit Indian mobile number",
      });
    }

    // Check if user exists
    const user = await User.findOne({ phone: cleanPhone });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not registered with this phone number",
      });
    }

    const otp = generateOtp();
    const expiresAt = new Date(
      Date.now() +
        Number(process.env.FAST2SMS_OTP_EXPIRE_MINUTES || 10) * 60 * 1000,
    );

    // Delete any existing OTP for this phone
    await Otp.deleteMany({ phone: cleanPhone });

    // Send OTP via Fast2SMS
    // const smsResult = await sendOtpViaFast2SMS(cleanPhone, otp);

    // if (!smsResult.success) {
    //   // Optionally, you might want to return error to client
    //   return res.status(500).json({
    //     success: false,
    //     message: "Failed to send OTP via SMS. Please try again.",
    //     error:
    //       process.env.NODE_ENV === "development" ? smsResult.error : undefined,
    //   });
    // }

    let smsResult = { success: true };

// ✅ Only send SMS in production
if (process.env.NODE_ENV === "production") {
  smsResult = await sendOtpViaFast2SMS(cleanPhone, otp);

  if (!smsResult.success) {
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP via SMS. Please try again.",
    });
  }
} else {
  console.log("🧪 DEV MODE: OTP NOT SENT VIA SMS");
  console.log("OTP =", otp);
}

    // Save OTP to database
    await Otp.create({
      phone: cleanPhone,
      email,
      otp,
      expiresAt,
      verified: false,
    });

    // In production, don't send OTP in response
    const response = {
      success: true,
      message: "OTP sent successfully to your mobile number",
      otp
    };

    // Only include OTP in development environment
    if (process.env.NODE_ENV === "development") {
      response.otp = otp;
      response.debug = smsResult.data;
    }

    res.status(200).json(response);
  } catch (error) {
    console.error("OTP Send Error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send OTP",
    });
  }
};

// Verify OTP API
export const loginVerifyOtp = async (req, res) => {
  try {
    let { phone, otp } = req.body;
    // phone = normalizePhone(phone);

    if (!phone || !otp) {
      return res.status(400).json({
        success: false,
        message: "Phone & OTP required",
      });
    }

    const otpRecord = await Otp.findOne({ phone, otp });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    if (otpRecord.expiresAt < new Date()) {
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

    // Mark OTP verified
    otpRecord.verified = true;
    await otpRecord.save();

    // 🔥 Find user by last 10 digits
    const last10Digits = phone.slice(-10);

    let user = await User.findOne({
      phone: { $regex: last10Digits + "$" },
    });

    if (user) {
      user.phoneVerified = true;
      await user.save();
    } else {
      console.log("User not found for phone:", phone);
    }

    await Otp.deleteMany({ phone });

    sendToken(user, 200, res);
  } catch (error) {
    console.error("OTP Verify Error:", error);
    res.status(500).json({
      success: false,
      message: "OTP verification failed",
    });
  }
};

// User Registration
export const register = catchAsyncErrors(async (req, res, next) => {
  const { email: rawEmail, phone } = req.body;

  // ✅ NORMALIZE EMAIL
  const email = normalizeEmail(rawEmail);

  // Email exists check
  const userExist = await User.findOne({ email });
  if (userExist) {
    return next(new Errorhandler("Email already registered", 400));
  }

  // Phone exists check (ignore empty phone)
  if (phone) {
    const userPhoneExist = await User.findOne({ phone });
    if (userPhoneExist) {
      return next(new Errorhandler("Phone already registered", 400));
    }
  }

  try {
    // 👇 ensure normalized email is saved
    const user = await User.create({
      ...req.body,
      email,
      mode: "seller",
    });

    // ✅ LINK EXISTING CONNECTIONS BASED ON PHONE
    if (user.phone) {
      const connections = await BuyerSellerConnection.find({
        buyerPhone: user.phone,
        buyer: null,
      });

      if (connections.length > 0) {
        await BuyerSellerConnection.updateMany(
          { buyerPhone: user.phone, buyer: null },
          { $set: { buyer: user._id } },
        );
      }
    }

    // Create Kiosk buyer category
    // await BuyerCategory.create({
    //   user: user._id,
    //   name: "Kiosk",
    //   discount: 0,
    //   color: "blue",
    // });

    // Create Standard buyer category
    await BuyerCategory.create({
      user: user._id,
      name: "Standard",
      discount: 0,
      color: "green",
    });

    // Also create payment options for both categories (with default Cash option)
    const buyerCategories = await BuyerCategory.find({ user: user._id });

    for (const category of buyerCategories) {
      await PaymentOption.create({
        paymentType: "Cash",
        buyerCategory: category._id,
        user: user._id,
        cashPayment: {
          discountPercent: 0,
        },
      });
    }

    sendToken(user, 200, res);
  } catch (error) {
    return next(
      new Errorhandler("Failed to create account. Please try again.", 500),
    );
  }
});

// user login
export const login = catchAsyncErrors(async (req, res, next) => {
  const { email, phone, password } = req.body;

  let searchQuery = {};

  if (email) {
    const normalizedEmail = normalizeEmail(email);
    searchQuery = { email: normalizedEmail };
  } else if (phone) {
    searchQuery = { phone };
  } else {
    return next(new Errorhandler("Please provide email or phone", 400));
  }

  // Find user by normalized email or phone
  const user = await User.findOne(searchQuery).select("+password");

  if (!user) {
    return next(new Errorhandler("Invalid email/phone or password", 401));
  }

  const isPasswordMatched = await user.comparePassword(password);

  if (!isPasswordMatched) {
    return next(new Errorhandler("Invalid email/phone or password", 401));
  }

  // ✅ Send token
  sendToken(user, 200, res);
});

// Google with register
export const googleWithRegister = catchAsyncErrors(async (req, res, next) => {
  const { tokenId } = req.body;

  const ticket = await client.verifyIdToken({
    idToken: tokenId,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  // 🔹 payload se raw email lo
  const { email: rawEmail, name } = ticket.getPayload();

  // ✅ normalize gmail (dot + plus + lowercase)
  const email = normalizeEmail(rawEmail);

  // 🔒 already registered check
  const userExist = await User.findOne({ email });
  if (userExist) {
    return next(
      new Errorhandler(
        "This Gmail account is already registered. Please login.",
        400,
      ),
    );
  }

  const randomPassword = crypto.randomBytes(20).toString("hex");

  const user = new User({
    name,
    email, // ✅ normalized email save
    password: randomPassword,
    emailVerified: true,
    phoneVerified: false,
  });

  // phone required bypass
  await user.save({ validateBeforeSave: false });

  // ✅ LINK EXISTING CONNECTIONS BASED ON PHONE
  if (user.phone) {
    const connections = await BuyerSellerConnection.find({
      buyerPhone: user.phone,
      buyer: null,
    });

    if (connections.length > 0) {
      await BuyerSellerConnection.updateMany(
        { buyerPhone: user.phone, buyer: null },
        { $set: { buyer: user._id } },
      );
    }
  }

  // await BuyerCategory.create({
  //   user: user._id,
  //   name: "Kiosk",
  //   discount: 0,
  // });
  // Create Standard buyer category
  await BuyerCategory.create({
    user: user._id,
    name: "Standard",
    discount: 0,
    color: "green",
  });

  // Also create payment options for both categories (with default Cash option)
  const buyerCategories = await BuyerCategory.find({ user: user._id });

  for (const category of buyerCategories) {
    await PaymentOption.create({
      paymentType: "Cash",
      buyerCategory: category._id,
      user: user._id,
      cashPayment: {
        discountPercent: 0,
      },
    });
  }

  sendToken(user, 200, res);
});

// Google with Login
export const googleWithlogin = catchAsyncErrors(async (req, res, next) => {
  const { tokenId } = req.body;

  const ticket = await client.verifyIdToken({
    idToken: tokenId,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const { email: rawEmail } = ticket.getPayload();

  // ✅ Google login में भी email normalize करें
  const email = normalizeEmail(rawEmail);

  const user = await User.findOne({ email });
  if (!user) {
    return next(new Errorhandler("User not found. Please register.", 404));
  }

  // Send JWT token
  sendToken(user, 200, res);
});

// Refresh Access Token
export const refreshAccessToken = catchAsyncErrors(async (req, res, next) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken)
    return next(new Errorhandler("Refresh token missing", 401));

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return next(new Errorhandler("User not found", 404));

    // Generate new access token
    const newAccessToken = user.getJWTToken();

    // Set new access token cookie
    res.cookie("token", newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 15 * 60 * 1000, // 15 min
      path: "/",
    });

    // Send token in response too
    return res.status(200).json({
      success: true,
      token: newAccessToken,
      expiresIn: 15 * 60,
    });
  } catch (err) {
    return next(new Errorhandler("Invalid refresh token", 403));
  }
});

// Logout
export const logout = catchAsyncErrors(async (req, res, next) => {
  res.clearCookie("token", { httpOnly: true, sameSite: "none", secure: true });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "none",
    secure: true,
  });

  res.status(200).json({
    success: true,
    message: "Logged out successfully",
  });
});

// user profile (Get User Details)
// export const profileDetails = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const user = await User.findById(req.user.id).select("-password");

//     if (!user) {
//       return next(new Errorhandler("User not found!", 404));
//     }
//     res.status(200).json({
//       success: true,
//       user,
//       message: "User info fetched successfully",
//     });
//   } catch (error) {
//     next(error);
//   }
// });

export const profileDetails = catchAsyncErrors(async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return next(new Errorhandler("User not found!", 404));
    }

    // Calculate profile completion percentage
    const calculateProfileCompletion = (user) => {
      let totalFields = 0;
      let completedFields = 0;

      // Define required fields based on user mode
      const requiredFields = {
        basic: ["name", "email", "phone"],
        allModes: ["businessName", "businessAddress"],
        seller: ["gstNumber"],
      };

      // Bank details fields (for sellers or users who need payment info)
      const bankFields = [
        "upiId",
        "bankName",
        "accountName",
        "accountNumber",
        "ifscCode",
        "branchName",
      ];

      // Check basic fields
      requiredFields.basic.forEach((field) => {
        totalFields++;
        if (user[field] && user[field].toString().trim() !== "") {
          completedFields++;
        }
      });

      // Check business fields (common for both buyer and seller)
      requiredFields.allModes.forEach((field) => {
        totalFields++;
        if (user[field] && user[field].toString().trim() !== "") {
          completedFields++;
        }
      });

      // If user is seller, check GST number
      if (user.mode === "seller") {
        requiredFields.seller.forEach((field) => {
          totalFields++;
          if (user[field] && user[field].toString().trim() !== "") {
            completedFields++;
          }
        });

        // For sellers, check bank details (optional but important)
        // You can adjust this based on your requirements
        bankFields.forEach((field) => {
          totalFields += 0.5; // Give half weight to each bank field
          if (
            user.bankDetails &&
            user.bankDetails[field] &&
            user.bankDetails[field].toString().trim() !== ""
          ) {
            completedFields += 0.5;
          }
        });

        // Check if bank account is verified
        // totalFields++;
        // if (user.bankDetails && user.bankDetails.accountVerified) {
        //   completedFields++;
        // }
      }

      // Check profile image (optional but adds to completion)
      totalFields++;
      if (user.profileImage && user.profileImage.url) {
        completedFields++;
      }

      // Check phone verification
      // totalFields++;
      // if (user.phoneVerified) {
      //   completedFields++;
      // }

      // // Check email verification
      // totalFields++;
      // if (user.emailVerified) {
      //   completedFields++;
      // }

      // Calculate percentage
      const percentage = Math.round((completedFields / totalFields) * 100);
      return Math.min(percentage, 100); // Ensure it doesn't exceed 100%
    };

    const completionPercentage = calculateProfileCompletion(user);

    // Get missing fields list
    const getMissingFields = (user) => {
      const missingFields = [];

      const checkField = (fieldName, fieldValue, fieldLabel) => {
        if (!fieldValue || fieldValue.toString().trim() === "") {
          missingFields.push(fieldLabel);
        }
      };

      const checkBankField = (fieldName, fieldValue, fieldLabel) => {
        if (!fieldValue || fieldValue.toString().trim() === "") {
          missingFields.push(fieldLabel);
        }
      };

      // Basic fields
      checkField("name", user.name, "Full Name");
      checkField("email", user.email, "Email");
      checkField("phone", user.phone, "Phone Number");

      // Business fields
      checkField("businessName", user.businessName, "Business Name");
      checkField("businessAddress", user.businessAddress, "Business Address");

      // Seller specific
      if (user.mode === "seller") {
        checkField("gstNumber", user.gstNumber, "GST Number");

        // Bank details for sellers
        if (!user.bankDetails || Object.keys(user.bankDetails).length === 0) {
          missingFields.push("Bank Details");
        } else {
          if (
            !user.bankDetails.bankName ||
            user.bankDetails.bankName.trim() === ""
          ) {
            missingFields.push("Bank Name");
          }
          if (
            !user.bankDetails.accountName ||
            user.bankDetails.accountName.trim() === ""
          ) {
            missingFields.push("Account Holder Name");
          }
          if (
            !user.bankDetails.accountNumber ||
            user.bankDetails.accountNumber.trim() === ""
          ) {
            missingFields.push("Account Number");
          }
          if (
            !user.bankDetails.ifscCode ||
            user.bankDetails.ifscCode.trim() === ""
          ) {
            missingFields.push("IFSC Code");
          }
          // if (!user.bankDetails.accountVerified) {
          //   missingFields.push("Bank Account Verification");
          // }
        }
      }

      // Profile image
      if (!user.profileImage || !user.profileImage.url) {
        missingFields.push("Profile Picture");
      }

      // Verifications
      // if (!user.phoneVerified) {
      //   missingFields.push("Phone Verification");
      // }
      // if (!user.emailVerified) {
      //   missingFields.push("Email Verification");
      // }

      return missingFields;
    };

    const missingFields = getMissingFields(user);

    // Get completion status for different sections
    const getSectionCompletion = (user) => {
      const sections = {
        basicInfo: {
          name: "Basic Information",
          completed: 0,
          total: 3, // name, email, phone
          fields: [
            {
              field: "name",
              label: "Full Name",
              completed: !!(user.name && user.name.trim()),
            },
            {
              field: "email",
              label: "Email",
              completed: !!(user.email && user.email.trim()),
            },
            {
              field: "phone",
              label: "Phone",
              completed: !!(user.phone && user.phone.trim()),
            },
          ],
        },
        businessInfo: {
          name: "Business Information",
          completed: 0,
          total: 2, // businessName, businessAddress
          fields: [
            {
              field: "businessName",
              label: "Business Name",
              completed: !!(user.businessName && user.businessName.trim()),
            },
            {
              field: "businessAddress",
              label: "Business Address",
              completed: !!(
                user.businessAddress && user.businessAddress.trim()
              ),
            },
          ],
        },
        // verification: {
        //   name: "Verifications",
        //   completed: 0,
        //   total: 2, // phoneVerified, emailVerified
        //   fields: [
        //     { field: "phoneVerified", label: "Phone Verification", completed: !!user.phoneVerified },
        //     { field: "emailVerified", label: "Email Verification", completed: !!user.emailVerified },
        //   ]
        // },
        profile: {
          name: "Profile",
          completed: 0,
          total: 1, // profileImage
          fields: [
            {
              field: "profileImage",
              label: "Profile Picture",
              completed: !!(user.profileImage && user.profileImage.url),
            },
          ],
        },
      };

      // Calculate completed for each section
      Object.keys(sections).forEach((sectionKey) => {
        const section = sections[sectionKey];
        section.completed = section.fields.filter((f) => f.completed).length;
        section.percentage = Math.round(
          (section.completed / section.total) * 100,
        );
      });

      // Add seller specific sections
      if (user.mode === "seller") {
        sections.taxInfo = {
          name: "Tax Information",
          completed: !!(user.gstNumber && user.gstNumber.trim()) ? 1 : 0,
          total: 1,
          percentage: !!(user.gstNumber && user.gstNumber.trim()) ? 100 : 0,
          fields: [
            {
              field: "gstNumber",
              label: "GST Number",
              completed: !!(user.gstNumber && user.gstNumber.trim()),
            },
          ],
        };

        sections.bankInfo = {
          name: "Bank Details",
          completed: 0,
          total: 7, // all bank fields + verification
          fields: [
            {
              field: "upiId",
              label: "UPI ID",
              completed: !!(
                user.bankDetails &&
                user.bankDetails.upiId &&
                user.bankDetails.upiId.trim()
              ),
            },
            {
              field: "bankName",
              label: "Bank Name",
              completed: !!(
                user.bankDetails &&
                user.bankDetails.bankName &&
                user.bankDetails.bankName.trim()
              ),
            },
            {
              field: "accountName",
              label: "Account Holder",
              completed: !!(
                user.bankDetails &&
                user.bankDetails.accountName &&
                user.bankDetails.accountName.trim()
              ),
            },
            {
              field: "accountNumber",
              label: "Account Number",
              completed: !!(
                user.bankDetails &&
                user.bankDetails.accountNumber &&
                user.bankDetails.accountNumber.trim()
              ),
            },
            {
              field: "ifscCode",
              label: "IFSC Code",
              completed: !!(
                user.bankDetails &&
                user.bankDetails.ifscCode &&
                user.bankDetails.ifscCode.trim()
              ),
            },
            {
              field: "branchName",
              label: "Branch Name",
              completed: !!(
                user.bankDetails &&
                user.bankDetails.branchName &&
                user.bankDetails.branchName.trim()
              ),
            },
            // { field: "accountVerified", label: "Account Verified", completed: !!(user.bankDetails && user.bankDetails.accountVerified) },
          ],
        };

        // Calculate bank info completion
        sections.bankInfo.completed = sections.bankInfo.fields.filter(
          (f) => f.completed,
        ).length;
        sections.bankInfo.percentage = Math.round(
          (sections.bankInfo.completed / sections.bankInfo.total) * 100,
        );
      }

      return sections;
    };

    const sectionCompletion = getSectionCompletion(user);

    res.status(200).json({
      success: true,
      user,
      profileCompletion: {
        percentage: completionPercentage,
        missingFields: missingFields,
        // sectionCompletion: sectionCompletion,
        isProfileComplete: completionPercentage >= 80, // 80% threshold
        nextSteps: missingFields.slice(0, 3), // Top 3 priority items
      },
      message: "User info fetched successfully",
    });
  } catch (error) {
    next(error);
  }
});

// user profile update
export const profileUpdate = catchAsyncErrors(async (req, res, next) => {
  const newData = {};

  // 1️⃣ Top-level fields clean
  Object.keys(req.body).forEach((key) => {
    if (
      req.body[key] !== "" &&
      req.body[key] !== null &&
      req.body[key] !== undefined &&
      key !== "bankDetails"
    ) {
      newData[key] = req.body[key];
    }
  });

  // 2️⃣ bankDetails clean separately
  if (req.body.bankDetails) {
    const cleanBankDetails = {};

    Object.keys(req.body.bankDetails).forEach((key) => {
      if (
        req.body.bankDetails[key] !== "" &&
        req.body.bankDetails[key] !== null &&
        req.body.bankDetails[key] !== undefined
      ) {
        cleanBankDetails[key] = req.body.bankDetails[key];
      }
    });

    // sirf tab add karo jab kuch valid ho
    if (Object.keys(cleanBankDetails).length > 0) {
      newData.bankDetails = cleanBankDetails;
    }
  }

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { $set: newData },
    {
      new: true,
      runValidators: true,
    },
  );
  console.log("user phone", user.phone);
  // ✅ LINK EXISTING CONNECTIONS BASED ON PHONE
  if (user.phone) {
    const connections = await BuyerSellerConnection.find({
      buyerPhone: user.phone,
      buyer: null,
    });

    if (connections.length > 0) {
      await BuyerSellerConnection.updateMany(
        { buyerPhone: user.phone, buyer: null },
        { $set: { buyer: user._id } },
      );
    }
  }
  res.status(200).json({
    success: true,
    user,
    message: "Profile updated successfully!",
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
      resetPasswordToken: user.resetPasswordToken,
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
export const resetPasswordverifyOtp = catchAsyncErrors(
  async (req, res, next) => {
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
    const hashedToken = crypto
      .createHash("sha256")
      .update(rawResetToken)
      .digest("hex");

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 mins more
    user.resetPasswordOtp = undefined; // remove OTP after verification
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      success: true,
      message: "OTP verified successfully",
      resetPasswordToken: rawResetToken, //  return raw token to frontend
    });
  },
);

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

    // Find user by hashed token and check expiry
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return next(
        new Errorhandler("Reset Password Token is invalid or has expired", 400),
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
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }

    const otp = generateOTP();
    const currentYear = new Date().getFullYear();

    // Update user or create if doesn't exist
    const user = await User.findOneAndUpdate(
      { email },
      {
        emailOtp: otp,
        emailOtpExpiry: Date.now() + 10 * 60 * 1000,
      },
      { new: true, upsert: true },
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
      message: "Something went wrong while sending the OTP.",
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
        message: "Email and OTP are required",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const numericOtp = parseInt(otp);
    if (isNaN(numericOtp)) {
      return res.status(400).json({
        success: false,
        message: "OTP must be a number",
      });
    }

    // Check OTP match
    if (user.emailOtp !== numericOtp) {
      return res.status(400).json({
        success: false,
        message: "Incorrect OTP",
      });
    }

    // Check expiry
    if (!user.emailOtpExpiry || user.emailOtpExpiry < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "OTP has expired",
      });
    }

    // Mark as verified and clear OTP
    user.emailVerified = true;
    user.emailOtp = null;
    user.emailOtpExpiry = null;

    await user.save();

    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("OTP verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// Send OTP to Phone
// export const sendOtpToPhone = async (req, res) => {
//   const { phone } = req.body;

//   if (!phone) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Phone number is required" });
//   }

//   const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
//   const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

//   try {
//     // Send OTP via Twilio
//     const sid = await sendOtp(phone, otp);

//     // Update or Create user with phone, OTP & expiry
//     let user = await User.findOne({ phone });

//     if (user) {
//       user.phoneOtp = otp;
//       user.phoneOtpExpiry = otpExpiry;
//       await user.save();
//     } else {
//       user = await User.create({
//         phone,
//         phoneOtp: otp,
//         phoneOtpExpiry: otpExpiry,
//       });
//     }

//     return res.status(200).json({
//       success: true,
//       message: "OTP sent and saved successfully",
//       sid,
//     });
//   } catch (err) {
//     return res.status(500).json({
//       success: false,
//       message: "Failed to send or save OTP",
//       error: err.message,
//     });
//   }
// };

// // Verify Phone OTP
// export const verifyPhoneOtp = async (req, res) => {
//   const { phone, otp } = req.body;

//   if (!phone || !otp) {
//     return res
//       .status(400)
//       .json({ success: false, message: "Phone and OTP are required." });
//   }

//   try {
//     const user = await User.findOne({ phone });

//     if (!user) {
//       return res
//         .status(404)
//         .json({ success: false, message: "User not found with this phone." });
//     }

//     // check if OTP matches
//     if (user.phoneOtp !== parseInt(otp, 10)) {
//       return res.status(400).json({ success: false, message: "Invalid OTP." });
//     }

//     // check if OTP expired
//     if (user.phoneOtpExpiry < new Date()) {
//       return res
//         .status(400)
//         .json({ success: false, message: "OTP has expired." });
//     }

//     // Success: verify phone
//     user.phoneVerified = true;
//     user.phoneOtp = null;
//     user.phoneOtpExpiry = null;

//     await user.save();

//     return res.status(200).json({
//       success: true,
//       message: "Phone number verified successfully.",
//     });
//   } catch (err) {
//     return res.status(500).json({
//       success: false,
//       message: "Failed to verify OTP.",
//       error: err.message,
//     });
//   }
// };

// Update User Mode (Buyer/Seller)
export const updateUserMode = async (req, res) => {
  try {
    const { id } = req.params;
    const { mode } = req.body;

    // Validate mode
    if (!["buyer", "seller"].includes(mode)) {
      return res.status(400).json({
        success: false,
        message: "Invalid mode. Only 'buyer' or 'seller' allowed.",
      });
    }

    // Find and update user
    const user = await User.findByIdAndUpdate(
      id,
      { mode },
      { new: true, runValidators: true },
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      message: "User mode updated successfully",
      data: {
        _id: user._id,
        name: user.name,
        email: user.email,
        mode: user.mode,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Get all users (Admin)
export const getAllUsers = catchAsyncErrors(async (req, res, next) => {
  const users = await User.find({ role: { $ne: 1 } })
    .select("-password")
    .sort({ createdAt: -1 });

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
      return next(new Errorhandler("User not found", 404));
    }
    res.status(200).json({
      success: true,
      deleteUser,
      message: "User deleted successfully",
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// export
// Upload Profile Image
export const uploadProfileImage = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if file is uploaded
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Please upload an image",
      });
    }

    // Upload image to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "profile-images",
      transformation: [
        { width: 500, height: 500, crop: "limit" },
        { quality: "auto:good" },
      ],
    });

    // Delete old image from Cloudinary if exists
    if (user.profileImage && user.profileImage.public_id) {
      await cloudinary.uploader.destroy(user.profileImage.public_id);
    }

    // Update user with new image
    user.profileImage = {
      url: result.secure_url,
      public_id: result.public_id,
    };

    await user.save();

    res.status(200).json({
      success: true,
      message: "Profile image uploaded successfully",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        profileImage: user.profileImage,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message || "Image upload failed",
    });
  }
};

// Delete Profile Image
export const deleteProfileImage = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if user has a profile image
    if (!user.profileImage || !user.profileImage.public_id) {
      return res.status(400).json({
        success: false,
        message: "No profile image found",
      });
    }

    // Delete image from Cloudinary
    await cloudinary.uploader.destroy(user.profileImage.public_id);

    // Remove image from user document
    user.profileImage = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Profile image deleted successfully",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        profileImage: null,
      },
    });
  } catch (error) {
    console.error("Delete profile image error:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Image deletion failed",
    });
  }
};
