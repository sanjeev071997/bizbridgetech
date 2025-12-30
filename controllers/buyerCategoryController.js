import BuyerCategory from '../models/buyerCategoriesModel.js';
import Errorhandler from '../utils/Errorhandler.js';
import catchAsyncErrors from '../middlewares/catchAsyncErrors.js';
import PaymentOption from '../models/paymentOption.js';

// Create new buyer category
// export const createBuyerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { name, discount, color } = req.body;

//   const category = await BuyerCategory.create({
//     user: req.user._id,
//     name,
//     discount,
//     color,
//   });

//   res.status(201).json({ success: true, data: category });
// });

// Create new buyer category with payment options api controller
export const createBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, discount, color, paymentOptions } = req.body;

  try {
    // 1. Validate required fields
    if (!name || !name.trim()) {
      return next(new Errorhandler("Buyer category name is required", 400));
    }

    if (!paymentOptions || !Array.isArray(paymentOptions) || paymentOptions.length === 0) {
      return next(new Errorhandler("At least one payment option is required", 400));
    }

    // 2. Create buyer category first
    const category = await BuyerCategory.create({
      user: req.user._id,
      name: name.trim(),
      discount: discount || 0,
      color: color || "purple",
    });

    // 3. Process payment options
    const cashOptions = paymentOptions.filter(opt => opt.type === "Cash");
    const creditOptions = paymentOptions.filter(opt => opt.type === "Credit");
    
    // Validate payment options
    if (cashOptions.length > 0) {
      for (const cashOption of cashOptions) {
        if (!cashOption.cashDiscount || cashOption.cashDiscount < 0 || cashOption.cashDiscount > 100) {
          return next(new Errorhandler("Cash discount must be between 0 and 100%", 400));
        }
      }
    }

    if (creditOptions.length > 0) {
      for (const creditOption of creditOptions) {
        if (!creditOption.creditPeriod || creditOption.creditPeriod < 1) {
          return next(new Errorhandler("Credit period must be at least 1 day", 400));
        }
        if (!creditOption.interestRate || creditOption.interestRate < 0) {
          return next(new Errorhandler("Interest rate must be a positive number", 400));
        }
        if (!creditOption.creditLimit || creditOption.creditLimit < 0) {
          return next(new Errorhandler("Credit limit must be a positive number", 400));
        }
      }
    }

    // 4. Determine payment type
    let paymentType = "";
    if (cashOptions.length > 0 && creditOptions.length > 0) {
      paymentType = "Both";
    } else if (cashOptions.length > 0) {
      paymentType = "Cash";
    } else if (creditOptions.length > 0) {
      paymentType = "Credit";
    }

    // 5. Prepare data for PaymentOption
    const paymentOptionData = {
      paymentType,
      buyerCategory: category._id,
      user: req.user._id,
    };

    // Add cash payment data if exists (take the first one if multiple)
    if (cashOptions.length > 0) {
      paymentOptionData.cashPayment = {
        discountPercent: cashOptions[0].cashDiscount
      };
    }

    // Add credit payment data if exists (take the first one if multiple)
    if (creditOptions.length > 0) {
      paymentOptionData.creditPayment = {
        creditPeriodDays: creditOptions[0].creditPeriod,
        interestRatePerYear: creditOptions[0].interestRate,
         interestStartAfterDays: creditOptions[0].creditPeriod,
        creditLimit:creditOptions[0].creditLimit,
      };
    }

    // 6. Create payment option
    const paymentOption = await PaymentOption.create(paymentOptionData);

    res.status(201).json({
      success: true,
      data: {
        category,
        paymentOption
      },
      message: "Buyer category created with payment options successfully"
    });

  } catch (error) {
    console.error("Error creating buyer category:", error);
    return next(new Errorhandler(error.message || "Failed to create buyer category", 500));
  }
});

// Get all categories for the logged-in user
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
// export const updateBuyerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { name, discount, color } = req.body;

//   const updated = await BuyerCategory.findOneAndUpdate(
//     { _id: req.params.id, user: req.user._id },
//     { name, discount, color },
//     { new: true, runValidators: true }
//   );

//   if (!updated) {
//     return next(new Errorhandler('Buyer category not found', 404));
//   }

//   res.status(200).json({ success: true, data: updated });
// });

// Update buyer category with payment options api controller
export const updateBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, discount, color, paymentOptions } = req.body;
  const { id } = req.params;

  try {
    // 1. Validate required fields
    if (!name || !name.trim()) {
      return next(new Errorhandler("Buyer category name is required", 400));
    }

    if (!paymentOptions || !Array.isArray(paymentOptions) || paymentOptions.length === 0) {
      return next(new Errorhandler("At least one payment option is required", 400));
    }

    // 2. Find and update buyer category
    const category = await BuyerCategory.findOneAndUpdate(
      { _id: id, user: req.user._id },
      { 
        name: name.trim(),
        discount: discount || 0,
        color: color || "purple",
      },
      { new: true, runValidators: true }
    );

    if (!category) {
      return next(new Errorhandler('Buyer category not found', 404));
    }

    // 3. Process payment options
    const cashOptions = paymentOptions.filter(opt => opt.type === "Cash");
    const creditOptions = paymentOptions.filter(opt => opt.type === "Credit");
    
    // Validate payment options
    if (cashOptions.length > 0) {
      for (const cashOption of cashOptions) {
        if (!cashOption.cashDiscount || cashOption.cashDiscount < 0 || cashOption.cashDiscount > 100) {
          return next(new Errorhandler("Cash discount must be between 0 and 100%", 400));
        }
      }
    }

    if (creditOptions.length > 0) {
      for (const creditOption of creditOptions) {
        if (!creditOption.creditPeriod || creditOption.creditPeriod < 1) {
          return next(new Errorhandler("Credit period must be at least 1 day", 400));
        }
        if (!creditOption.interestRate || creditOption.interestRate < 0) {
          return next(new Errorhandler("Interest rate must be a positive number", 400));
        }
        if (!creditOption.creditLimit || creditOption.creditLimit < 0) {
          return next(new Errorhandler("Credit limit must be a positive number", 400));
        }
      }
    }

    // 4. Determine payment type
    let paymentType = "";
    if (cashOptions.length > 0 && creditOptions.length > 0) {
      paymentType = "Both";
    } else if (cashOptions.length > 0) {
      paymentType = "Cash";
    } else if (creditOptions.length > 0) {
      paymentType = "Credit";
    }

    // 5. Prepare data for PaymentOption update
    const paymentOptionUpdateData = {
      paymentType,
      user: req.user._id,
    };

    // Add cash payment data if exists
    if (cashOptions.length > 0) {
      paymentOptionUpdateData.cashPayment = {
        discountPercent: cashOptions[0].cashDiscount
      };
    } else {
      paymentOptionUpdateData.cashPayment = null;
    }

    // Add credit payment data if exists
    if (creditOptions.length > 0) {
      paymentOptionUpdateData.creditPayment = {
        creditPeriodDays: creditOptions[0].creditPeriod,
        interestRatePerYear: creditOptions[0].interestRate,
        creditLimit: creditOptions[0].creditLimit,
        interestStartAfterDays: creditOptions[0].creditPeriod
      };
    } else {
      paymentOptionUpdateData.creditPayment = null;
    }

    // 6. Find existing payment option or create new one
    let paymentOption = await PaymentOption.findOne({ buyerCategory: category._id });

    if (paymentOption) {
      // Update existing payment option
      paymentOption = await PaymentOption.findByIdAndUpdate(
        paymentOption._id,
        paymentOptionUpdateData,
        { new: true, runValidators: true }
      );
    } else {
      // Create new payment option
      paymentOptionUpdateData.buyerCategory = category._id;
      paymentOption = await PaymentOption.create(paymentOptionUpdateData);
    }

    res.status(200).json({
      success: true,
      data: {
        category,
        paymentOption
      },
      message: "Buyer category updated with payment options successfully"
    });

  } catch (error) {
    console.error("Error updating buyer category:", error);
    return next(new Errorhandler(error.message || "Failed to update buyer category", 500));
  }
});

// Delete a Buyer category
// export const deleteBuyerCategory = catchAsyncErrors(async (req, res, next) => {
//   const deleted = await BuyerCategory.findOneAndDelete({
//     _id: req.params.id,
//     user: req.user._id,
//   });

//   if (!deleted) {
//     return next(new Errorhandler('Buyer category not found', 404));
//   }

//   res.status(200).json({ success: true, message: 'Buyer category deleted successfully' });
// });

// Delete buyer category with its payment option api controller
export const deleteBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  try {
    // 1. First find the category to check if it exists
    const category = await BuyerCategory.findOne({
      _id: id,
      user: req.user._id,
    });

    if (!category) {
      return next(new Errorhandler('Buyer category not found', 404));
    }

    // 2. Delete associated payment options
    await PaymentOption.deleteMany({ 
      buyerCategory: id 
    });

    // 3. Delete the buyer category
    await BuyerCategory.deleteOne({
      _id: id,
      user: req.user._id,
    });

    res.status(200).json({ 
      success: true, 
      message: 'Buyer category and associated payment options deleted successfully' 
    });

  } catch (error) {
    console.error("Error deleting buyer category:", error);
    return next(new Errorhandler(error.message || "Failed to delete buyer category", 500));
  }
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