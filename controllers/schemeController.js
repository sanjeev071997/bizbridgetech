import Scheme from "../models/schemeModel.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import Errorhandler from '../utils/Errorhandler.js';
import catchAsyncErrors from '../middlewares/catchAsyncErrors.js';


// Create Scheme
export const createScheme = catchAsyncErrors(async (req, res, next) => {
  const { title, type, details} = req.body;

  const scheme = await Scheme.create({
    title,
    type,
    details,
    user: req.user._id,
  });

  res.status(201).json({
    success: true,
    message: "Scheme created successfully",
    data: scheme
  });
});

// Get All Schemes (only active = true and buyer-seller connected)
export const getAllSchemes = catchAsyncErrors(async (req, res, next) => {
  try {
    const buyerId = req.user._id; // current logged-in user

    // Step 1: find all connections where this user is buyer
    const connections = await BuyerSellerConnection.find({ buyer: buyerId, status: "Accepted" }).select("seller");

    const sellerIds = connections.map(c => c.seller);

    // Step 2: find schemes from connected sellers
    const schemes = await Scheme.find({
      active: true,
      user: { $in: sellerIds }
    }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: schemes.length,
      data: schemes
    });
  } catch (error) {
    next(error);
  }
});



// // Get Scheme by ID
// export const getSchemeById = catchAsyncErrors(async (req, res, next) => {
//   const scheme = await Scheme.findById(req.params.id);
//   if (!scheme) {
//     return next(new Errorhandler("Scheme not found", 404));
//   }
//   res.status(200).json({ success: true, data: scheme });
// });

// Get Scheme by ID
export const getSchemeById = catchAsyncErrors(async (req, res, next) => {
  try {
    const buyerId = req.user._id; // current logged-in user
    const schemeId = req.params.id;

    // Step 1: find all connections where this user is buyer
    const connections = await BuyerSellerConnection.find({
      buyer: buyerId,
      status: "Accepted"
    }).select("seller");

    const sellerIds = connections.map(c => c.seller);

    // Step 2: find scheme by ID from connected sellers only
    const scheme = await Scheme.findOne({
      _id: schemeId,
      active: true,
      user: { $in: sellerIds }
    });

    if (!scheme) {
      return next(new Errorhandler("Scheme not found or not accessible", 404));
    }

    res.status(200).json({
      success: true,
      data: scheme
    });
  } catch (error) {
    next(error);
  }
});


// Update Scheme
export const updateScheme = catchAsyncErrors(async (req, res, next) => {
  let scheme = await Scheme.findById(req.params.id);
  if (!scheme) {
    return next(new Errorhandler("Scheme not found", 404));
  }

  scheme = await Scheme.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true
  });

  res.status(200).json({
    success: true,
    message: "Scheme updated successfully",
    data: scheme
  });
});

// Delete Scheme
export const deleteScheme = catchAsyncErrors(async (req, res, next) => {
  const scheme = await Scheme.findById(req.params.id);
  if (!scheme) {
    return next(new Errorhandler("Scheme not found", 404));
  }

  await scheme.deleteOne();

  res.status(200).json({
    success: true,
    message: "Scheme deleted successfully"
  });
});

// Toggle Active Status
export const toggleSchemeStatus = catchAsyncErrors(async (req, res, next) => {
  const scheme = await Scheme.findById(req.params.id);
  if (!scheme) {
    return next(new Errorhandler("Scheme not found", 404));
  }

  scheme.active = !scheme.active;
  await scheme.save();

  res.status(200).json({
    success: true,
    message: `Scheme ${scheme.active ? "activated" : "deactivated"} successfully`,
    data: scheme
  });
});
