import PaymentOption from '../models/paymentOption.js';
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Create Payment Option
export const createPaymentOption = catchAsyncErrors(async (req, res, next) => {
  let {
    paymentType,
    cashPayment,
    creditPayment,
    buyerCategory,
    user,
  } = req.body;

  // Validation
  if (!paymentType) {
    return next(new Errorhandler("Payment type is required", 400));
  }

  //  FIX: Auto-set interestStartAfterDays
  if (creditPayment && creditPayment.creditPeriodDays) {
    creditPayment.interestStartAfterDays = creditPayment.creditPeriodDays;
  }

  // Create in DB
  const newPaymentOption = await PaymentOption.create({
    paymentType,
    cashPayment,
    creditPayment,
    buyerCategory,
    user,
  });

  res.status(201).json({
    success: true,
    message: "Payment option created successfully",
    data: newPaymentOption,
  });
});


//  Get All Payment Options
export const getAllPaymentOptions = catchAsyncErrors(async (req, res, next) => {
  const paymentOptions = await PaymentOption.find().sort({ createdAt: -1 });

  res.status(200).json({
    success: true,
    count: paymentOptions.length,
    data: paymentOptions,
  });
});

//  Get Single Payment Option
export const getPaymentOptionById = catchAsyncErrors(async (req, res, next) => {
  const paymentOption = await PaymentOption.findById(req.params.id);

  if (!paymentOption) {
    return next(new Errorhandler("Payment option not found", 404));
  }

  res.status(200).json({
    success: true,
    data: paymentOption,
  });
});

// //  Update Payment Option
// export const updatePaymentOption = catchAsyncErrors(async (req, res, next) => {
//   console.log("Update Request Body:", req.body); // Debugging line
//   const updatedPaymentOption = await PaymentOption.findByIdAndUpdate(
//     req.params.id,
//     req.body,
//     { new: true, runValidators: true }
//   );

//   if (!updatedPaymentOption) {
//     return next(new Errorhandler("Payment option not found", 404));
//   }

//   res.status(200).json({
//     success: true,
//     message: "Payment option updated successfully",
//     data: updatedPaymentOption,
//   });
// });

//  Update Payment Option
export const updatePaymentOption = catchAsyncErrors(async (req, res, next) => {
  console.log("Update Request Body:", req.body);

  let {
    paymentType,
    cashPayment,
    creditPayment,
  } = req.body;

  // -----------------------------------------
  // FIX 1: Auto-set interestStartAfterDays
  // -----------------------------------------
  if (creditPayment && creditPayment.creditPeriodDays) {
    creditPayment.interestStartAfterDays = creditPayment.creditPeriodDays;
  }

  // -----------------------------------------
  // FIX 2: Prevent null values (important)
  // -----------------------------------------
  if (paymentType === "Cash") {
    creditPayment = null;
  } else if (paymentType === "Credit") {
    cashPayment = null;
  }

  // Build updated payload
  const payload = {
    paymentType,
    cashPayment,
    creditPayment,
  };

  const updatedPaymentOption = await PaymentOption.findByIdAndUpdate(
    req.params.id,
    payload,
    { new: true, runValidators: true }
  );

  if (!updatedPaymentOption) {
    return next(new Errorhandler("Payment option not found", 404));
  }

  res.status(200).json({
    success: true,
    message: "Payment option updated successfully",
    data: updatedPaymentOption,
  });
});


//  Delete Payment Option
export const deletePaymentOption = catchAsyncErrors(async (req, res, next) => {
  const deletedPaymentOption = await PaymentOption.findByIdAndDelete(req.params.id);

  if (!deletedPaymentOption) {
    return next(new Errorhandler("Payment option not found", 404));
  }

  res.status(200).json({
    success: true,
    message: "Payment option deleted successfully",
  });
});

// get payment option by user
export const getPaymentOptionByUser = catchAsyncErrors(async (req, res, next) => {
    const user = req.params.id;
    // Validate user ID
    if (!user) {
        return next(new Errorhandler("User ID is required", 400));
    }
    // Find payment options for the authenticated user
  const paymentOptions = await PaymentOption.find({user}).populate("buyerCategory", "name discount").sort({ createdAt: -1 });
    if (!paymentOptions || paymentOptions.length === 0) {
        return next(new Errorhandler("No payment options found for this user", 404));
    }
    res.status(200).json({
        success: true,
        data: paymentOptions,
    });
}); 

// get payment option by buyer category
export const getPaymentOptionBybuyer = catchAsyncErrors(async (req, res, next) => {
    const { buyerCategory, seller } = req.body;
     // Validation
  if (!buyerCategory || !seller) {
    return next(new Errorhandler("Both buyerCategory and sellerId are required", 400));
  }
    // Find payment options for the given buyer category
  const paymentOptions = await PaymentOption.find({ buyerCategory, user:seller }).populate("buyerCategory", "name discount").sort({ createdAt: -1 });
    if (!paymentOptions || paymentOptions.length === 0) {
        return next(new Errorhandler("No payment options found for this buyer category", 404));
    }
    res.status(200).json({
        success: true,
        data: paymentOptions,
    });
});