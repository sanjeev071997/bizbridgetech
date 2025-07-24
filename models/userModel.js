import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      unique: true,
      required: true,
    },

    password: {
      type: String,
      unique: true,
      select: false,
      required: true,
    },

    phone: {
      type: String,
      required: true,
    },

    role: {
      type: Number,
      default: 0, // 0-> Normal User, 1-> Admin, 2-> sub-Admin. 3-> Editor
    },

    resetPasswordOtp: {
      type: String,
    },

    resetPasswordToken: String,

    resetPasswordExpire: Date,
  },

  {
    timestamps: true,
  }
);

// Before saving, hash the password if it's not already hashed
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  // Check if the password is already hashed using the bcrypt format
  if (!isPasswordAlreadyHashed(this.password)) {
    this.password = await bcrypt.hash(this.password, 10);
  } else {
    console.log("Password is already hashed. Skipping hashing.");
  }
  next();
});

// Function to check if the password is already hashed (you can use a regex for bcrypt hash format)
const isPasswordAlreadyHashed = (password) => {
  // Regex pattern for bcrypt hashed passwords
  return /^$2[ayb]\$.{56}$/.test(password);
};

// Compare Password
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Create JWT TOKEN
userSchema.methods.getJWTToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// Generating password Reset Token (Forgot Password)
userSchema.methods.getResetPasswordToken = function () {
  // Generating Token
  const resetToken = crypto.randomBytes(40).toString("hex");
  // Hashing and adding resetPasswordToken to userSchema
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

const userModel = mongoose.model("users", userSchema);

export default userModel;
