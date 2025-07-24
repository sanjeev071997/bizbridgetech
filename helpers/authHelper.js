import Errorhandler from "../utils/Errorhandler.js";

// Register Validation
export const registerValidation = (req, res, next) => {
  const { name, email, phone, password } = req.body;
  if (!name) {
    return next(new Errorhandler("Please Enter Your Full Name", 400));
  }
  if (!email) {
    return next(new Errorhandler("Please Enter Your Email", 400));
  }
  if (!phone) {
    return next(new Errorhandler("Please Enter Your Phone Number", 400));
  }
  if (!password) {
    return next(new Errorhandler("Please Enter Your Password", 400));
  }

  if (name.length < 3) {
    return next(
      new Errorhandler(
        `${name} - Full Name should have more than 3 characters`,
        403
      )
    );
  }

  // Email validation
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    return next(new Errorhandler(`${email} - is not a valid email`, 403));
  }

  // Phone validation pattern to allow any country code followed by 10 digits
  const phonePattern = /^\+\d{1,3}\s?[0-9]{10}$/;

  if (!phonePattern.test(phone)) {
    return next(
      new Errorhandler(
        `${req.body.phone} - Invalid phone number format. Please use a valid country code followed by a 10-digit number, like "+91 998XXXXXXX".`,
        403
      )
    );
  }

  // Password validation
  const pattern = new RegExp("(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8,}");
  if (!pattern.test(password)) {
    return next(
      new Errorhandler(
        `Password must contain at least one digit, one lowercase letter, one uppercase letter, and be at least 8 characters long`,
        403
      )
    );
  }

  next();
};

// Login Validation
export const loginValidation = (req, res, next) => {
  const { email, password } = req.body;
  if (!email) {
    return next(new Errorhandler("Please Enter Your Email", 400));
  }
  if (!password) {
    return next(new Errorhandler("Please Enter Your Password", 400));
  }

  next();
};

// Profile Update Validation
export const profileUpdateValidation = (req, res, next) => {
  if (req.body.name.length < 3 || req.body.studentName < 3) {
    return next(
      new Errorhandler(
        `${req.body.name} - Full Name should have more than 3 characters`,
        403
      )
    );
  }

  // Email validation
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(req.body.email)) {
    return next(
      new Errorhandler(`${req.body.email} - is not a valid email`, 403)
    );
  }

  // Phone validation pattern to allow any country code followed by 10 digits
  const phonePattern = /^\+\d{1,3}\s?[0-9]{10}$/;

  if (!phonePattern.test(req.body.phone)) {
    return next(
      new Errorhandler(
        `${req.body.phone} - Invalid phone number format. Please use a valid country code followed by a 10-digit number, like "+91 998XXXXXXX".`,
        403
      )
    );
  }

  next();
};

// Profile Update Password Validation
export const profileUpdatePasswordValidation = (req, res, next) => {
  if (!req.body.oldPassword) {
    return next(new Errorhandler("Please enter an old password", 403));
  }

  if (!req.body.newPassword) {
    return next(new Errorhandler("Please enter an new password", 403));
  }

  if (!req.body.confirmPassword) {
    return next(new Errorhandler("Please enter an confirm password", 403));
  }
  // newPassword validation
  const pattern = new RegExp("(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8,}");
  if (!pattern.test(req.body.newPassword)) {
    return next(
      new Errorhandler(
        `Password must contain at least one digit, one lowercase letter, one uppercase letter, and be at least 8 characters long`,
        403
      )
    );
  }
  next();
};
// Reset Password (confirm password) Validation
export const resetPasswordValidation = (req, res, next) => {
  if (!req.body.password) {
    return next(new Errorhandler("Please enter new password", 400));
  }

  if (!req.body.confirmPassword) {
    return next(new Errorhandler("Please enter confirm password", 400));
  }

  next();
};