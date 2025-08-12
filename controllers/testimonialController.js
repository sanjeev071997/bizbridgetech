import Testimonial from '../models/testimonialsModel.js';
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import Errorhandler from "../utils/Errorhandler.js";
import cloudinary from "../utils/cloudinary.js";

// Function to handle base64 image uploads
const uploadBase64Image = async (base64Image) => {
  try {
    const result = await cloudinary.uploader.upload(base64Image, {
      folder: "Testimonial",
    });
    return {
      image: result.secure_url,
      cloudinaryId: result.public_id,
    };
  } catch (error) {
    throw new Error("Error uploading base64 image");
  }
};

// Create Testimonial
export const createTestimonial = catchAsyncErrors(async (req, res, next) => {
   const { name, image, description, companyName, designation } = req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image; 
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      const result = await cloudinary.uploader.upload(image, {
        folder: "Testimonial",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    if (!imageUrl) {
      return next(new Errorhandler("Image upload failed", 400));
    }

    const newTestimonial = await Testimonial.create({
      user: req.user._id,
      name,
      image: imageUrl,
      cloudinaryId,
      description, 
      companyName, 
      designation
    });

    res.status(200).json({
      success: true,
      message: "Testimonial created successfully",
      newTestimonial,
    });
  } catch (error) {
    console.log("Detailed Error:", error);
    return next(
      new Errorhandler("Error processing testimonial upload or creation", 500)
    );
  }
});

// Get All Testimonials
export const getAllTestimonials = catchAsyncErrors(async (req, res, next) => {
  const testimonials = await Testimonial.find().sort({ createdAt: -1 });

  res.status(200).json({
    success: true,
    testimonials,
  });
});

//  Get Testimonials by req.user._id
export const getUserTestimonials = catchAsyncErrors(async (req, res, next) => {
  const userId = req.user._id;
  const testimonials = await Testimonial.find({ user: userId }).sort({ createdAt: -1 });

  res.status(200).json({
    success: true,
    testimonials,
  });
});

//  Update Testimonial
export const updateTestimonial = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { name, image, description, companyName, designation } = req.body;

  const testimonial = await Testimonial.findById(id);
  if (!testimonial) {
    return next(new Errorhandler("Testimonial not found", 404));
  }

  // Permission check
  if (testimonial.user.toString() !== req.user._id.toString()) {
    return next(new Errorhandler("Unauthorized", 403));
  }

  let imageUrl = testimonial.image;
  let cloudinaryId = testimonial.cloudinaryId;

  // Image update if new image provided
  if (image && image !== testimonial.image) {
    // Delete old image
    if (cloudinaryId) {
      await cloudinary.uploader.destroy(cloudinaryId);
    }

    if (image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    } else {
      const result = await cloudinary.uploader.upload(image, {
        folder: "Testimonial",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }
  }

  testimonial.name = name || testimonial.name;
  testimonial.image = imageUrl;
  testimonial.cloudinaryId = cloudinaryId;
  testimonial.description = description || testimonial.description;
  testimonial.companyName = companyName || testimonial.companyName;
  testimonial.designation = designation || testimonial.designation;

  await testimonial.save();

  res.status(200).json({
    success: true,
    message: "Testimonial updated successfully",
    testimonial,
  });
});

//  Delete Testimonial
export const deleteTestimonial = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  const testimonial = await Testimonial.findById(id);
  if (!testimonial) {
    return next(new Errorhandler("Testimonial not found", 404));
  }

  // Permission check
  if (testimonial.user.toString() !== req.user._id.toString()) {
    return next(new Errorhandler("Unauthorized", 403));
  }

  // Delete image from cloudinary
  if (testimonial.cloudinaryId) {
    await cloudinary.uploader.destroy(testimonial.cloudinaryId);
  }

  await Testimonial.findByIdAndDelete(id);  

  res.status(200).json({
    success: true,
    message: "Testimonial deleted successfully",
  });
});

