import BuyerCategory from '../models/buyerCategoriesModel.js';
import Errorhandler from '../utils/Errorhandler.js';
import catchAsyncErrors from '../middlewares/catchAsyncErrors.js';
import PaymentOption from '../models/paymentOption.js';
import Product from "../models/sellerProductModel.js"

// Create new buyer category with payment options api controller
// export const createBuyerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { name, discount, color, paymentOptions } = req.body;

//   try {
//     // 1. Validate required fields
//     if (!name || !name.trim()) {
//       return next(new Errorhandler("Buyer category name is required", 400));
//     }

//     if (!paymentOptions || !Array.isArray(paymentOptions) || paymentOptions.length === 0) {
//       return next(new Errorhandler("At least one payment option is required", 400));
//     }

//     // 2. Create buyer category first
//     const category = await BuyerCategory.create({
//       user: req.user._id,
//       name: name.trim(),
//       discount: discount || 0,
//       color: color || "purple",
//     });

//     // 3. Process payment options
//     const cashOptions = paymentOptions.filter(opt => opt.type === "Cash");
//     const creditOptions = paymentOptions.filter(opt => opt.type === "Credit");
    
//     // Validate payment options
//     if (cashOptions.length > 0) {
//       for (const cashOption of cashOptions) {
//         if (!cashOption.cashDiscount || cashOption.cashDiscount < 0 || cashOption.cashDiscount > 100) {
//           return next(new Errorhandler("Cash discount must be between 0 and 100%", 400));
//         }
//       }
//     }

//     if (creditOptions.length > 0) {
//       for (const creditOption of creditOptions) {
//         if (!creditOption.creditPeriod || creditOption.creditPeriod < 1) {
//           return next(new Errorhandler("Credit period must be at least 1 day", 400));
//         }
//         if (!creditOption.interestRate || creditOption.interestRate < 0) {
//           return next(new Errorhandler("Interest rate must be a positive number", 400));
//         }
//         if (!creditOption.creditLimit || creditOption.creditLimit < 0) {
//           return next(new Errorhandler("Credit limit must be a positive number", 400));
//         }
//       }
//     }

//     // 4. Determine payment type
//     let paymentType = "";
//     if (cashOptions.length > 0 && creditOptions.length > 0) {
//       paymentType = "Both";
//     } else if (cashOptions.length > 0) {
//       paymentType = "Cash";
//     } else if (creditOptions.length > 0) {
//       paymentType = "Credit";
//     }

//     // 5. Prepare data for PaymentOption
//     const paymentOptionData = {
//       paymentType,
//       buyerCategory: category._id,
//       user: req.user._id,
//     };

//     // Add cash payment data if exists (take the first one if multiple)
//     if (cashOptions.length > 0) {
//       paymentOptionData.cashPayment = {
//         discountPercent: cashOptions[0].cashDiscount
//       };
//     }

//     // Add credit payment data if exists (take the first one if multiple)
//     if (creditOptions.length > 0) {
//       paymentOptionData.creditPayment = {
//         creditPeriodDays: creditOptions[0].creditPeriod,
//         interestRatePerYear: creditOptions[0].interestRate,
//          interestStartAfterDays: creditOptions[0].creditPeriod,
//         creditLimit:creditOptions[0].creditLimit,
//       };
//     }

//     // 6. Create payment option
//     const paymentOption = await PaymentOption.create(paymentOptionData);

//     res.status(201).json({
//       success: true,
//       data: {
//         category,
//         paymentOption
//       },
//       message: "Buyer category created with payment options successfully"
//     });

//   } catch (error) {
//     console.error("Error creating buyer category:", error);
//     return next(new Errorhandler(error.message || "Failed to create buyer category", 500));
//   }
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

    // ✅ **NEW CODE START: Add this buyer category to ALL existing products**
    // Get all products of this seller (current user)
    const sellerProducts = await Product.find({ user: req.user._id });
    
    if (sellerProducts.length > 0) {
      const bulkOperations = [];
      
      for (const product of sellerProducts) {
        const mrp = parseFloat(product.mrp) || 0;
        const calculatedPrice = mrp - (mrp * (discount || 0)) / 100;
        
        bulkOperations.push({
          updateOne: {
            filter: { 
              _id: product._id,
              "productVisibility.buyerCategory": { $ne: category._id }
            },
            update: {
              $push: {
                productVisibility: {
                  buyerCategory: category._id,
                  visible: true, // Default: visible
                  price: calculatedPrice,
                  isPriceManuallySet: false,
                  lastPriceUpdate: new Date()
                }
              }
            }
          }
        });
      }
      
      if (bulkOperations.length > 0) {
        await Product.bulkWrite(bulkOperations);
        console.log(`Added buyer category ${category.name} to ${bulkOperations.length} products`);
      }
    }
    // ✅ **NEW CODE END**

    // 3. Process payment options (your existing code...)
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
        creditLimit: creditOptions[0].creditLimit,
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

// export const createBuyerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { name, discount, color, paymentOptions } = req.body;

//   try {
//     /* ───────────────────────── 1. VALIDATION ───────────────────────── */

//     if (!name || !name.trim()) {
//       return next(new Errorhandler("Buyer category name is required", 400));
//     }

//     if (!paymentOptions || !Array.isArray(paymentOptions) || paymentOptions.length === 0) {
//       return next(new Errorhandler("At least one payment option is required", 400));
//     }

//     /* ──────────────────────── 2. CREATE CATEGORY ─────────────────────── */

//     const category = await BuyerCategory.create({
//       user: req.user._id,
//       name: name.trim(),
//       discount: discount || 0,
//       color: color || "purple",
//     });

//     /* ───────────── 3. ADD CATEGORY TO ALL PRODUCTS (NO DUPLICATE) ───────────── */

//     const sellerProducts = await Product.find({ user: req.user._id });

//     if (sellerProducts.length > 0) {
//       const bulkOperations = [];

//       // snapshot object (exact format frontend needs)
//       const buyerCategorySnapshot = {
//         _id: category._id,
//         name: category.name,
//         discount: String(category.discount),
//       };

//       for (const product of sellerProducts) {
//         const mrp = Number(product.mrp) || 0;
//         const calculatedPrice =
//           mrp - (mrp * (category.discount || 0)) / 100;

//         bulkOperations.push({
//           updateOne: {
//             filter: {
//               _id: product._id,
//               "productVisibility.buyerCategory._id": { $ne: category._id }, // ✅ prevent duplicate
//             },
//             update: {
//               $push: {
//                 productVisibility: {
//                   buyerCategory: buyerCategorySnapshot,
//                   visible: true,
//                   price: Math.round(calculatedPrice),
//                   isPriceManuallySet: false,
//                   lastPriceUpdate: new Date(),
//                 },
//               },
//             },
//           },
//         });
//       }

//       if (bulkOperations.length > 0) {
//         await Product.bulkWrite(bulkOperations);
//       }
//     }

//     /* ──────────────────────── 4. PAYMENT OPTIONS ─────────────────────── */

//     const cashOptions = paymentOptions.filter(opt => opt.type === "Cash");
//     const creditOptions = paymentOptions.filter(opt => opt.type === "Credit");

//     // Cash validation
//     for (const cash of cashOptions) {
//       if (cash.cashDiscount < 0 || cash.cashDiscount > 100) {
//         return next(new Errorhandler("Cash discount must be between 0 and 100%", 400));
//       }
//     }

//     // Credit validation
//     for (const credit of creditOptions) {
//       if (!credit.creditPeriod || credit.creditPeriod < 1) {
//         return next(new Errorhandler("Credit period must be at least 1 day", 400));
//       }
//       if (credit.interestRate < 0) {
//         return next(new Errorhandler("Interest rate must be positive", 400));
//       }
//       if (credit.creditLimit < 0) {
//         return next(new Errorhandler("Credit limit must be positive", 400));
//       }
//     }

//     /* ──────────────────────── 5. PAYMENT TYPE ─────────────────────── */

//     let paymentType = "";
//     if (cashOptions.length && creditOptions.length) paymentType = "Both";
//     else if (cashOptions.length) paymentType = "Cash";
//     else if (creditOptions.length) paymentType = "Credit";

//     /* ──────────────────────── 6. CREATE PAYMENT OPTION ─────────────────────── */

//     const paymentOptionData = {
//       user: req.user._id,
//       buyerCategory: category._id,
//       paymentType,
//     };

//     if (cashOptions.length) {
//       paymentOptionData.cashPayment = {
//         discountPercent: cashOptions[0].cashDiscount,
//       };
//     }

//     if (creditOptions.length) {
//       paymentOptionData.creditPayment = {
//         creditPeriodDays: creditOptions[0].creditPeriod,
//         interestRatePerYear: creditOptions[0].interestRate,
//         interestStartAfterDays: creditOptions[0].creditPeriod,
//         creditLimit: creditOptions[0].creditLimit,
//       };
//     }

//     const paymentOption = await PaymentOption.create(paymentOptionData);

//     /* ───────────────────────── RESPONSE ───────────────────────── */

//     res.status(201).json({
//       success: true,
//       message: "Buyer category created successfully",
//       data: {
//         category,
//         paymentOption,
//       },
//     });

//   } catch (error) {
//     console.error("Create Buyer Category Error:", error);
//     return next(
//       new Errorhandler(error.message || "Failed to create buyer category", 500)
//     );
//   }
// });


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
    .populate("user", "name phone ProfileImage.url")
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

// Delete buyer category with its payment option api controller
// export const deleteBuyerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;

//   try {
//     // 1. First find the category to check if it exists
//     const category = await BuyerCategory.findOne({
//       _id: id,
//       user: req.user._id,
//     });

//     if (!category) {
//       return next(new Errorhandler('Buyer category not found', 404));
//     }

//     // 2. Delete associated payment options
//     await PaymentOption.deleteMany({ 
//       buyerCategory: id 
//     });

//     // 3. Delete the buyer category
//     await BuyerCategory.deleteOne({
//       _id: id,
//       user: req.user._id,
//     });

//     res.status(200).json({ 
//       success: true, 
//       message: 'Buyer category and associated payment options deleted successfully' 
//     });

//   } catch (error) {
//     console.error("Error deleting buyer category:", error);
//     return next(new Errorhandler(error.message || "Failed to delete buyer category", 500));
//   }
// });
export const deleteBuyerCategory = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  try {
    const category = await BuyerCategory.findOne({
      _id: id,
      user: req.user._id,
    });

    if (!category) {
      return next(new Errorhandler("Buyer category not found", 404));
    }

    // delete payment options
    await PaymentOption.deleteMany({ buyerCategory: id });

    // ✅ ONLY delete this buyerCategory from productVisibility
    await Product.updateMany(
      {
        user: req.user._id,
        "productVisibility.buyerCategory": category._id,
      },
      {
        $pull: {
          productVisibility: {
            buyerCategory: category._id,
          },
        },
      }
    );

    // delete buyer category
    await BuyerCategory.deleteOne({
      _id: id,
      user: req.user._id,
    });

    res.status(200).json({
      success: true,
      message: "Buyer category deleted safely",
    });
  } catch (error) {
    console.error(error);
    return next(new Errorhandler("Failed to delete buyer category", 500));
  }
});


// Admin: Get all buyer categories

export const adminGetAllBuyerCategories = catchAsyncErrors(async (req, res, next) => {
  let categories;  

  // Only admin (role === 1) can see all categories
  if (req.user.role === 1) {
    categories = await BuyerCategory.find().populate('user', 'name email phone ProfileImage.url').sort({ createdAt: -1 });
  } else {
    categories = await BuyerCategory.find({ user: req.user._id });
  }

  res.status(200).json({ success: true, data: categories });
});
