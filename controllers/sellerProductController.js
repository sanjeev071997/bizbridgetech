import Product from "../models/sellerProductModel.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import Errorhandler from "../utils/errorHandler.js";
import cloudinary from "../utils/cloudinary.js";
 
// Function to handle base64 image uploads
const uploadBase64Image = async (base64Image) => {
  try {
    const result = await cloudinary.uploader.upload(base64Image, {
      folder: "SallerProducts",
    });
    return {
      image: result.secure_url,
      cloudinaryId: result.public_id,
    };
  } catch (error) {
    throw new Error("Error uploading base64 image");
  }
};

// Function to add a new product
export const addProduct = catchAsyncErrors(async (req, res, next) => {
  const { name, image, price, category } = req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image; 
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      const result = await cloudinary.uploader.upload(image, {
        folder: "SallerProducts",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    if (!imageUrl) {
      return next(new Errorhandler("Image upload failed", 400));
    }

    const newProduct = await Product.create({
      user: req.user._id,
      name,
      image: imageUrl,
      cloudinaryId,
      price,
      category, 
    });

    res.status(200).json({
      success: true,
      message: "Product added successfully",
      product: newProduct,
    });
  } catch (error) {
    console.log("Detailed Error:", error);
    return next(
      new Errorhandler("Error processing product upload or creation", 500)
    );
  }
});


// Function to get all products
export const getAllProducts = catchAsyncErrors(async (req, res, next) => {
  try {
    const products = await Product.find()
      .populate("category", "name")
      .sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      products,
    });
  } catch (error) {
    console.log("Detailed Error:", error);
    return next(new Errorhandler("Error fetching products", 500));
  }
});

// Function to delete a product
export const deleteProduct = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  try {
    const product = await Product.findById(id);
    if (!product) {
      return next(new Errorhandler("Product not found", 404));
    }
    if (product.cloudinaryId) {
      await cloudinary.uploader.destroy(product.cloudinaryId);
    }
    await Product.findByIdAndDelete(id);
    res.status(200).json({
      success: true,
      message: "Product deleted successfully",
    });
  } catch (error) {
    console.log("Detailed Error:", error);
    return next(new Errorhandler("Error deleting product", 500));
  }
});

// Function to update a product
export const updateProduct = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { name, image, price, category } = req.body;

  try {
    const product = await Product.findById(id);
    if (!product) {
      return next(new Errorhandler("Product not found", 404));
    }
    let imageUrl = product.image;
    let cloudinaryId = product.cloudinaryId;
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.url;
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      if (product.cloudinaryId) {
        await cloudinary.uploader.destroy(product.cloudinaryId);
      }
      const result = await cloudinary.uploader.upload(image, {
        folder: "SallerProducts",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }
    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      {
        // user: req.user._id,
        name,
        image: imageUrl,
        cloudinaryId,
        price,
        category,
      },
      { new: true }
    );
    res.status(200).json({
      success: true,
      message: "Product updated successfully",
      updatedProduct,
    });
  } catch (error) {
    console.log("Detailed Error:", error);
    return next(new Errorhandler("Error updating product", 500));
  }
});

// Function to get a product by ID
export const getProductById = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  console.log(id, "product id");
  
  try {
    const product = await Product.findById(id).populate("category", "name");
    if (!product) {
      return next(new Errorhandler("Product not found", 404));
    }
    res.status(200).json({
      success: true,
      product,
    });
  } catch (error) {
    console.log("Detailed Error:", error);
    return next(new Errorhandler("Error fetching product", 500));
  }
});

// Function to get products by category ID
export const getProductsByCategoryId = catchAsyncErrors(
  async (req, res, next) => {
    const { category } = req.params;
    try {
      const products = await Product.find({ category })
        .populate("category", "name")
        .sort({ createdAt: -1 });
      if (products.length === 0) {
        return next(
          new Errorhandler("No products found for this category", 404)
        );
      }
      res.status(200).json({
        success: true,
        products,
      });
    } catch (error) {
      console.log("Detailed Error:", error);
      return next(new Errorhandler("Error fetching products by category", 500));
    }
  }
);
