import SellerCategory from '../models/sellercategoriesModel.js';
import Errorhandler from '../utils/Errorhandler.js';
import catchAsyncErrors from '../middlewares/catchAsyncErrors.js';

// Create new seller category
export const createSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, gst } = req.body;

  const category = await SellerCategory.create({
    user: req.user._id,
    name,
    gst,
  });

  res.status(201).json({ success: true, data: category });
});

// Get all categories for the logged-in user
export const getAllSellerCategories = catchAsyncErrors(async (req, res, next) => {
  const categories = await SellerCategory.find({ user: req.user._id });

  res.status(200).json({ success: true, data: categories });
});

// Get single category by ID
export const getSellerCategoryById = catchAsyncErrors(async (req, res, next) => {
  const category = await SellerCategory.findOne({
    _id: req.params.id,
    user: req.user._id,
  });

  if (!category) {
    return next(new Errorhandler('Seller category not found', 404));
  }

  res.status(200).json({ success: true, data: category });
});

// Update a category
export const updateSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, gst } = req.body;

  const updated = await SellerCategory.findOneAndUpdate(
    { _id: req.params.id, user: req.user._id },
    { name, gst },
    { new: true, runValidators: true }
  );

  if (!updated) {
    return next(new Errorhandler('Seller category not found', 404));
  }

  res.status(200).json({ success: true, data: updated });
});

// Delete a category
export const deleteSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const deleted = await SellerCategory.findOneAndDelete({
    _id: req.params.id,
    user: req.user._id,
  });

  if (!deleted) {
    return next(new Errorhandler('Seller category not found', 404));
  }

  res.status(200).json({ success: true, message: 'Seller category deleted successfully' });
});

// Admin: Get all seller categories
export const adminGetAllSellerCategories = catchAsyncErrors(async (req, res, next) => {
  let categories;

  // Only admin (role === 1) can see all categories
  if (req.user.role === 1) {
    categories = await SellerCategory.find().populate('user', 'name email, phone'); 
  } else {
    // Other users only see their own categories
    categories = await SellerCategory.find({ user: req.user._id });
  }

  res.status(200).json({ success: true, data: categories });
});