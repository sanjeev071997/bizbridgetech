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
export const createSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, gst, image } = req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
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

    // Create category
    const category = await SellerCategory.create({
      user: req.user._id,
      name,
      gst,
      image: imageUrl,
      cloudinaryId,
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
//   const { name, gst } = req.body;

//   const updated = await SellerCategory.findOneAndUpdate(
//     { _id: req.params.id, user: req.user._id },
//     { name, gst },
//     { new: true, runValidators: true }
//   );

//   if (!updated) {
//     return next(new Errorhandler("Seller category not found", 404));
//   }

//   res.status(200).json({ success: true, data: updated });
// });
export const updateSellerCategory = catchAsyncErrors(async (req, res, next) => {
  const { name, gst, image } = req.body;

  // Find category first
  const category = await SellerCategory.findOne({
    _id: req.params.id,
    user: req.user._id,
  });

  if (!category) {
    return next(new Errorhandler("Seller category not found", 404));
  }

  let imageUrl = category.image;          // default old image
  let cloudinaryId = category.cloudinaryId;

  try {
    // 🔥 CASE 1: Base64 new image
    if (image && image.startsWith("data:image")) {
      // delete old image if exists
      if (cloudinaryId) {
        await cloudinary.uploader.destroy(cloudinaryId);
      }

      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    }

    // 🔥 CASE 2: Local file upload (normal file path)
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
      imageUrl = image;      // use as is
      cloudinaryId = "";     // no Cloudinary file
    }

    // Update record
    const updated = await SellerCategory.findByIdAndUpdate(
      req.params.id,
      {
        name,
        gst,
        image: imageUrl,
        cloudinaryId,
      },
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
// export const deleteSellerCategory = catchAsyncErrors(async (req, res, next) => {
//   const deleted = await SellerCategory.findOneAndDelete({
//     _id: req.params.id,
//     user: req.user._id,
//   });

//   if (!deleted) {
//     return next(new Errorhandler("Seller category not found", 404));
//   }

//   res
//     .status(200)
//     .json({ success: true, message: "Seller category deleted successfully" });
// });

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
