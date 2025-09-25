import Product from "../models/sellerProductModel.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import Errorhandler from "../utils/Errorhandler.js";
import cloudinary from "../utils/cloudinary.js";
import BuyerCategory from "../models/buyerCategoriesModel.js";
 
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

// // Function to add a new product
// export const addProduct = catchAsyncErrors(async (req, res, next) => {
//   const { name, image, mrp, category, stock, buyerCategory } = req.body;

//   let imageUrl = "";
//   let cloudinaryId = "";

//   try {
//     // Image upload handling
//     if (image && image.startsWith("data:image")) {
//       const result = await uploadBase64Image(image);
//       imageUrl = result.image; 
//       cloudinaryId = result.cloudinaryId;
//     } else if (image) {
//       const result = await cloudinary.uploader.upload(image, {
//         folder: "SallerProducts",
//       });
//       imageUrl = result.secure_url;
//       cloudinaryId = result.public_id;
//     }

//     if (!imageUrl) {
//       return next(new Errorhandler("Image upload failed", 400));
//     }

//     // discount calculate
//     let discount = 0;
//     if (buyerCategory && buyerCategory.discount) {
//       discount = buyerCategory.discount; // मान लो discount % में आ रहा है
//     }

//     let price = mrp;
//     if (discount > 0) {
//       price = mrp - (mrp * discount / 100); // discounted price
//     }

//     // Product create
//     const newProduct = await Product.create({
//       user: req.user._id,
//       name,
//       image: imageUrl,
//       cloudinaryId,
//       mrp,
//       price,   // final price after discount
//       category,
//       stock,
//       buyerCategory
//     });

//     res.status(200).json({
//       success: true,
//       message: "Product added successfully",
//       product: newProduct,
//     });
//   } catch (error) {
//     console.log("Detailed Error:", error);
//     return next(
//       new Errorhandler("Error processing product upload or creation", 500)
//     );
//   }
// });

// Function to add a new product
export const addProduct = catchAsyncErrors(async (req, res, next) => {
  const { name, image, mrp, category, stock, buyerCategory } = req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    // Image upload handling
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

    // get buyerCategory discount from DB
    let discount = 0;
    if (buyerCategory) {
      const buyerCatData = await BuyerCategory.findById(buyerCategory).select("discount");
      if (buyerCatData && buyerCatData.discount) {
        discount = buyerCatData.discount; // percentage
      }
    }

    // price calculation
    let price = mrp;
    if (discount > 0) {
      price = mrp - (mrp * discount / 100);
    }

    // Product create
    const newProduct = await Product.create({
      user: req.user._id,
      name,
      image: imageUrl,
      cloudinaryId,
      mrp,
      price,   // final price after discount
      category,
      stock,
      buyerCategory
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
    let { page = 1, limit = 10 } = req.query;
    page = parseInt(page, 10);
    limit = parseInt(limit, 10);

    const skip = (page - 1) * limit;

    let query = Product.find()
      .populate("category", "name gst")
      .populate("user", "name phone")
      .populate("buyerCategory", "name discount")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Conditionally populate user details if role === 1 (superadmin)
    if (req.user.role === 1) {
      query = query.populate("user", "name phone");
    }

    const products = await query;
    const totalProducts = await Product.countDocuments();

    res.status(200).json({
      success: true,
      page,
      totalPages: Math.ceil(totalProducts / limit),
      totalProducts,
      data: products,
    });
  } catch (error) {
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

    // Permission check: only product owner or role 1 user can delete
    if (
      product.user.toString() !== req.user._id.toString() &&
      req.user.role !== 1
    ) {
      return next(new Errorhandler("You are not authorized to delete this product", 403));
    }

    // Delete from Cloudinary if needed
    if (product.cloudinaryId) {
      await cloudinary.uploader.destroy(product.cloudinaryId);
    }

    // Delete product from DB
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

// // Function to update a product
// export const updateProduct = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;
//   const { name, image, mrp, price, category,stock, buyerCategory } = req.body;

//   try {
//     const product = await Product.findById(id);
//     if (!product) {
//       return next(new Errorhandler("Product not found", 404));
//     }
//     // Permission check: only product owner or role 1 user can update
//     if (
//       product.user.toString() !== req.user._id.toString() &&
//       req.user.role !== 1
//     ) {
//       return next(new Errorhandler("You are not authorized to update this product", 403));
//     }
//     let imageUrl = product.image;
//     let cloudinaryId = product.cloudinaryId;
//     if (image && image.startsWith("data:image")) {
//       const result = await uploadBase64Image(image);
//       imageUrl = result.url;
//       cloudinaryId = result.cloudinaryId;
//     } else if (image) {
//       if (product.cloudinaryId) {
//         await cloudinary.uploader.destroy(product.cloudinaryId);
//       }
//       const result = await cloudinary.uploader.upload(image, {
//         folder: "SallerProducts",
//       });
//       imageUrl = result.secure_url;
//       cloudinaryId = result.public_id;
//     }
//     const updatedProduct = await Product.findByIdAndUpdate(
//       id,
//       {
//         // user: req.user._id,
//         name,
//         image: imageUrl,
//         cloudinaryId,
//         mrp,
//         price,
//         category,
//         stock,
//         buyerCategory
//       },
//       { new: true }
//     ).populate("category", "name gst")
//       .populate("user", "name phone")
//       .populate("buyerCategory", "name discount");
//     res.status(200).json({
//       success: true,
//       message: "Product updated successfully",
//       updatedProduct,
//     });
//   } catch (error) {
//     console.log("Detailed Error:", error);
//     return next(new Errorhandler("Error updating product", 500));
//   }
// });
// Function to update a product
export const updateProduct = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { name, image, mrp, category, stock, buyerCategory } = req.body;

  try {
    const product = await Product.findById(id);
    if (!product) {
      return next(new Errorhandler("Product not found", 404));
    }

    // Permission check: only product owner or role 1 user can update
    if (
      product.user.toString() !== req.user._id.toString() &&
      req.user.role !== 1
    ) {
      return next(
        new Errorhandler("You are not authorized to update this product", 403)
      );
    }

    // Handle image update
    let imageUrl = product.image;
    let cloudinaryId = product.cloudinaryId;
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
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

    // Discount calculation from buyerCategory DB
    let discount = 0;
    if (buyerCategory) {
      const buyerCatData = await BuyerCategory.findById(buyerCategory).select("discount");
      if (buyerCatData && buyerCatData.discount) {
        discount = buyerCatData.discount;
      }
    }

    let price = mrp || product.mrp;
    if (discount > 0) {
      price = price - (price * discount / 100);
    }

    // Update product
    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      {
        name,
        image: imageUrl,
        cloudinaryId,
        mrp,
        price, // final discounted price
        category,
        stock,
        buyerCategory
      },
      { new: true }
    )
      .populate("category", "name gst")
      .populate("user", "name phone")
      .populate("buyerCategory", "name discount");

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
  try {
    const product = await Product.findById(id).populate("category", "name gst").populate("user", "name phone").populate("buyerCategory", "name discount");
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
        .populate("category", "name gst")
        .populate("user", "name phone")
        .populate("buyerCategory", "name discount")
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

// Function to get a product by ID
export const getProductByUserId = catchAsyncErrors(async (req, res, next) => {
  const  user  = req.user.id;
  console.log(user, "saller user product id")
  try {
    const product = await Product.find({user:user}).populate("category", "name gst").populate("user", "name phone").populate("buyerCategory", "name discount");
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

// Get Buyer Category Products
export const getProductsByBuyerCategoryId = catchAsyncErrors(
  async (req, res, next) => {
    const { buyerCategory } = req.params;
    try {
      const products = await Product.find({ buyerCategory })
        .populate("category", "name gst")
        .populate("user", "name phone")
        .populate("buyerCategory", "name discount")
        .sort({ createdAt: -1 });
      if (products.length === 0) {
        return next(
          new Errorhandler("No products found for this buyer category", 404)
        );
      }
      res.status(200).json({
        success: true,
        products,
      });
    } catch (error) {
      console.log("Detailed Error:", error);
      return next(new Errorhandler("Error fetching products by buyer category", 500));
    }
  }
);
