import BuyerCategory from '../models/buyerCategoriesModel.js';
import Errorhandler from '../utils/Errorhandler.js';
import catchAsyncErrors from '../middlewares/catchAsyncErrors.js';

// Create new buyer category
export const createBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, discount } = req.body;

  const category = await BuyerCategory.create({
    user: req.user._id,
    name,
    discount,
  });

  res.status(201).json({ success: true, data: category });
});

// Get all categories for the logged-in user
// export const getAllBuyerCategories = catchAsyncErrors(async (req, res, next) => {
//   const categories = await BuyerCategory.find({ user: req.user._id }).sort({ createdAt: -1 }).populate("user", "name phone")

//   res.status(200).json({ success: true, data: categories });
// });

export const getAllBuyerCategories = catchAsyncErrors(async (req, res, next) => {
  let { page = 1, limit = 10 } = req.query;

  // Convert to numbers
  page = parseInt(page);
  limit = parseInt(limit);

  // Count total documents for the logged-in user
  const totalCategories = await BuyerCategory.countDocuments({ user: req.user._id });

  // Fetch paginated data
  const categories = await BuyerCategory.find({ user: req.user._id })
    .sort({ createdAt: -1 })
    .populate("user", "name phone")
    .skip((page - 1) * limit)
    .limit(limit);

  res.status(200).json({
    success: true,
    total: totalCategories,
    page,
    limit,
    totalPages: Math.ceil(totalCategories / limit),
    data: categories,
  });
});


// Get single category by ID
export const getBuyerCategoryById = catchAsyncErrors(async (req, res, next) => {
  const category = await BuyerCategory.findOne({
    _id: req.params.id,
    user: req.user._id,
  });

  if (!category) {
    return next(new Errorhandler('Buyer category not found', 404));
  }

  res.status(200).json({ success: true, data: category });
});

// Update a category
export const updateBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, discount } = req.body;

  const updated = await BuyerCategory.findOneAndUpdate(
    { _id: req.params.id, user: req.user._id },
    { name, discount },
    { new: true, runValidators: true }
  );

  if (!updated) {
    return next(new Errorhandler('Buyer category not found', 404));
  }

  res.status(200).json({ success: true, data: updated });
});

// Delete a Buyer category
export const deleteBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const deleted = await BuyerCategory.findOneAndDelete({
    _id: req.params.id,
    user: req.user._id,
  });

  if (!deleted) {
    return next(new Errorhandler('Buyer category not found', 404));
  }

  res.status(200).json({ success: true, message: 'Buyer category deleted successfully' });
});

// Admin: Get all buyer categories
export const adminGetAllBuyerCategories = catchAsyncErrors(async (req, res, next) => {
  let categories;  

  // Only admin (role === 1) can see all categories
  if (req.user.role === 1) {
    categories = await BuyerCategory.find().populate('user', 'name email phone').sort({ createdAt: -1 });
  } else {
    categories = await BuyerCategory.find({ user: req.user._id });
  }

  res.status(200).json({ success: true, data: categories });
});