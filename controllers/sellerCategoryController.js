import SellerCategory from "../models/sellercategoriesModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import cloudinary from "../utils/cloudinary.js";

// Function to handle base64 image uploads
const uploadBase64Image = async (base64Image) => {
  try {
    const result = await cloudinary.uploader.upload(base64Image, {
      folder: "SallerCategory",
    });
    return {
      image: result.secure_url,
      cloudinaryId: result.public_id,
    };
  } catch (error) {
    throw new Error("Error uploading base64 image");
  }
};

// Create new seller category
// export const createSellerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { name, gst, image, hsnCode } = req.body;

//   let imageUrl = "";
//   let cloudinaryId = "";

//   try {
//     // CASE 1: Base64 IMAGE
//     if (image && image.startsWith("data:image")) {
//       const result = await uploadBase64Image(image);
//       imageUrl = result.image;
//       cloudinaryId = result.cloudinaryId;
//     }

//     // CASE 2: Local file path
//     else if (image && !image.startsWith("http")) {
//       const result = await cloudinary.uploader.upload(image, {
//         folder: "SellerCategory",
//       });
//       imageUrl = result.secure_url;
//       cloudinaryId = result.public_id;
//     }

//     // CASE 3: Direct URL
//     else if (image?.startsWith("http")) {
//       imageUrl = image;
//       cloudinaryId = "";
//     }

//     // Create category
//     const category = await SellerCategory.create({
//       user: req.user._id,
//       name,
//       gst,
//       image: imageUrl,
//       cloudinaryId,
//       hsnCode
//     });

//     return res.status(201).json({
//       success: true,
//       message: "Category added successfully",
//       data: category,
//     });
//   } catch (error) {
//     console.error("Seller Category Error:", error);
//     return next(
//       new Errorhandler("Error processing category upload or creation", 500)
//     );
//   }
// });

export const createSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, gst, image, hsnCode } = req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    // 1. Validate required fields
    if (!name || !name.trim()) {
      return next(new Errorhandler("Category name is required", 400));
    }

    // 2. Check if category with same name already exists for this user
    const existingCategory = await SellerCategory.findOne({
      user: req.user._id,
      name: name.trim()
    });

    if (existingCategory) {
      return next(new Errorhandler(`Category with name "${name.trim()}" already exists`, 400));
    }

    // 3. Process GST - set to 0 if not provided
    const gstValue = gst !== undefined && gst !== null && gst !== "" ? gst : 0;

    // 4. Validate GST if provided
    if (gstValue !== 0) {
      const gstNum = parseFloat(gstValue);
      if (isNaN(gstNum) || gstNum < 0 || gstNum > 100) {
        return next(new Errorhandler("GST must be between 0 and 100%", 400));
      }
    }

    // 5. Handle image upload
    // CASE 1: Base64 IMAGE
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    }

    // CASE 2: Local file path
    else if (image && !image.startsWith("http")) {
      const result = await cloudinary.uploader.upload(image, {
        folder: "SellerCategory",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    // CASE 3: Direct URL
    else if (image?.startsWith("http")) {
      imageUrl = image;
      cloudinaryId = "";
    }

    // 6. Create category
    const category = await SellerCategory.create({
      user: req.user._id,
      name: name.trim(),
      gst: gstValue,
      image: imageUrl,
      cloudinaryId,
      hsnCode: hsnCode || ""
    });

    return res.status(201).json({
      success: true,
      message: "Category added successfully",
      data: category,
    });
  } catch (error) {
    console.error("Seller Category Error:", error);
    return next(
      new Errorhandler("Error processing category upload or creation", 500)
    );
  }
});

// Get all categories for the logged-in user with pagination
export const getAllSellerCategories = catchAsyncErrors(
  async (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const categories = await SellerCategory.find({ user: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await SellerCategory.countDocuments({ user: req.user._id });

    res.status(200).json({
      success: true,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      data: categories,
    });
  }
);

// Get single category by ID
export const getSellerCategoryById = catchAsyncErrors(
  async (req, res, next) => {
    const category = await SellerCategory.findOne({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!category) {
      return next(new Errorhandler("Seller category not found", 404));
    }

    res.status(200).json({ success: true, data: category });
  }
);

// Update a category
// export const updateSellerCategory = catchAsyncErrors(async (req, res, next) => {
//   const { name, gst, image, hsnCode } = req.body;

//   // Find category first
//   const category = await SellerCategory.findOne({
//     _id: req.params.id,
//     user: req.user._id,
//   });

//   if (!category) {
//     return next(new Errorhandler("Seller category not found", 404));
//   }

//   let imageUrl = category.image;          // default old image
//   let cloudinaryId = category.cloudinaryId;

//   try {
//     // 🔥 CASE 1: Base64 new image
//     if (image && image.startsWith("data:image")) {
//       // delete old image if exists
//       if (cloudinaryId) {
//         await cloudinary.uploader.destroy(cloudinaryId);
//       }

//       const result = await uploadBase64Image(image);
//       imageUrl = result.image;
//       cloudinaryId = result.cloudinaryId;
//     }

//     // 🔥 CASE 2: Local file upload (normal file path)
//     else if (image && !image.startsWith("http")) {
//       if (cloudinaryId) {
//         await cloudinary.uploader.destroy(cloudinaryId);
//       }

//       const result = await cloudinary.uploader.upload(image, {
//         folder: "SellerCategory",
//       });

//       imageUrl = result.secure_url;
//       cloudinaryId = result.public_id;
//     }

//     // 🔥 CASE 3: Direct URL (no Cloudinary upload)
//     else if (image && image.startsWith("http")) {
//       imageUrl = image;      // use as is
//       cloudinaryId = "";     // no Cloudinary file
//     }

//     // Update record
//     const updated = await SellerCategory.findByIdAndUpdate(
//       req.params.id,
//       {
//         name,
//         gst,
//         image: imageUrl,
//         cloudinaryId,
//         hsnCode
//       },
//       { new: true, runValidators: true }
//     );

//     return res.status(200).json({
//       success: true,
//       message: "Category updated successfully",
//       data: updated,
//     });
//   } catch (error) {
//     console.error("Update Seller Category Error:", error);
//     return next(
//       new Errorhandler("Error updating seller category", 500)
//     );
//   }
// });

export const updateSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, gst, image, hsnCode } = req.body;
  const { id } = req.params;

  try {
    // 1. Find category first
    const category = await SellerCategory.findOne({
      _id: id,
      user: req.user._id,
    });

    if (!category) {
      return next(new Errorhandler("Seller category not found", 404));
    }

    // 2. Check for duplicate name (excluding current category)
    if (name && name.trim()) {
      const duplicateCategory = await SellerCategory.findOne({
        user: req.user._id,
        name: name.trim(),
        _id: { $ne: id }
      });

      if (duplicateCategory) {
        return next(new Errorhandler(`Category with name "${name.trim()}" already exists`, 400));
      }
    }

    let imageUrl = category.image;          // default old image
    let cloudinaryId = category.cloudinaryId;

    // 3. Process GST - keep existing if not provided, otherwise set to 0 if empty/null
    let gstValue = category.gst; // Default to existing value
    
    if (gst !== undefined && gst !== null) {
      if (gst === "" || gst === null) {
        gstValue = 0; // Set to 0 if empty or null
      } else {
        gstValue = gst;
      }
    }

    // 4. Validate GST if provided
    if (gstValue !== undefined && gstValue !== null) {
      const gstNum = parseFloat(gstValue);
      if (isNaN(gstNum) || gstNum < 0 || gstNum > 100) {
        return next(new Errorhandler("GST must be between 0 and 100%", 400));
      }
    }

    // 5. Handle image upload
    // CASE 1: Base64 new image
    if (image && image.startsWith("data:image")) {
      // delete old image if exists
      if (cloudinaryId) {
        await cloudinary.uploader.destroy(cloudinaryId);
      }

      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    }

    //  CASE 2: Local file upload (normal file path)
    else if (image && !image.startsWith("http")) {
      if (cloudinaryId) {
        await cloudinary.uploader.destroy(cloudinaryId);
      }

      const result = await cloudinary.uploader.upload(image, {
        folder: "SellerCategory",
      });

      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    // 🔥 CASE 3: Direct URL (no Cloudinary upload)
    else if (image && image.startsWith("http")) {
      // Delete old Cloudinary image if exists
      if (cloudinaryId) {
        await cloudinary.uploader.destroy(cloudinaryId);
      }
      imageUrl = image;      // use as is
      cloudinaryId = "";     // no Cloudinary file
    }

    // 6. Prepare update data
    const updateData = {
      image: imageUrl,
      cloudinaryId,
      hsnCode: hsnCode !== undefined ? hsnCode : category.hsnCode
    };

    // Only update name if provided
    if (name && name.trim()) {
      updateData.name = name.trim();
    }

    // Only update GST if provided or explicitly set to null/empty
    if (gst !== undefined && gst !== null) {
      updateData.gst = gst === "" ? 0 : gst;
    }

    // 7. Update record
    const updated = await SellerCategory.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    );

    return res.status(200).json({
      success: true,
      message: "Category updated successfully",
      data: updated,
    });
  } catch (error) {
    console.error("Update Seller Category Error:", error);
    return next(
      new Errorhandler("Error updating seller category", 500)
    );
  }
});
// Delete a category
export const deleteSellerCategory = catchAsyncErrors(async (req, res, next) => {
  // Find category first (so we can delete image also)
  const category = await SellerCategory.findOne({
    _id: req.params.id,
    user: req.user._id,
  });

  if (!category) {
    return next(new Errorhandler("Seller category not found", 404));
  }

  try {
    // DELETE IMAGE FROM CLOUDINARY
    if (category.cloudinaryId) {
      await cloudinary.uploader.destroy(category.cloudinaryId);
    }

    // DELETE CATEGORY FROM DB
    await SellerCategory.findByIdAndDelete(req.params.id);

    return res.status(200).json({
      success: true,
      message: "Seller category deleted successfully",
    });
  } catch (error) {
    console.error("Delete Seller Category Error:", error);
    return next(
      new Errorhandler("Error deleting seller category or its image", 500)
    );
  }
});

// Admin: Get all seller categories
export const adminGetAllSellerCategories = catchAsyncErrors(
  async (req, res, next) => {
    let categories;

    // Only admin (role === 1) can see all categories
    if (req.user.role === 1) {
      categories = await SellerCategory.find()
        .populate("user", "name email phone")
        .sort({ createdAt: -1 });
    } else {
      categories = await SellerCategory.find({ user: req.user._id });
    }

    res.status(200).json({ success: true, data: categories });
  }
);
