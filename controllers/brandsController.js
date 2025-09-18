import Brands from "../models/brandsModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import cloudinary from "../utils/cloudinary.js";

// Function to handle base64 image uploads
const uploadBase64Image = async (base64Image) => {
  try {
    const result = await cloudinary.uploader.upload(base64Image, {
      folder: "Brands",
    });
    return {
      image: result.secure_url,
      cloudinaryId: result.public_id,
    };
  } catch (error) {
    throw new Error("Error uploading base64 image");
  }
};

// create brand
export const createBrand = catchAsyncErrors(async (req, res, next) => {
  const { image } = req.body;
const user = req.user.id;

  if (!user) {
    return next(new Errorhandler("Please provide all required fields", 400));
  }

  let imageData = {};

  if (image) {
    if (image.startsWith("data:image/")) {
      // Handle base64 image
      imageData = await uploadBase64Image(image);
    } else {
      // Handle URL image
      const result = await cloudinary.uploader.upload(image, {
        folder: "Brands",
      });
      imageData = {
        image: result.secure_url,
        cloudinaryId: result.public_id,
      };
    }
  }

  const newBrand = new Brands({
    user,
    ...imageData,
  });

  await newBrand.save();

  res.status(201).json({
    success: true,
    message: "Brand created successfully",
    brand: newBrand,
  });
});

// get all brands
export const getAllBrands = catchAsyncErrors(async (req, res, next) => {
  const brands = await Brands.find()
//   .populate("user")
 .sort({ createdAt: -1 });

  res.status(200).json({
    success: true,
    brands,
  });
});

// delete brand
export const deleteBrand = catchAsyncErrors(async (req, res, next) => {
  const brand = await Brands.findById(req.params.id);

  if (!brand) {
    return next(new Errorhandler("Brand not found", 404));
  }

  // Delete image from Cloudinary
  if (brand.cloudinaryId) {
    await cloudinary.uploader.destroy(brand.cloudinaryId);
  }

  await Brands.findByIdAndDelete(req.params.id);

  res.status(200).json({
    success: true,
    message: "Brand deleted successfully",
  });
}); 