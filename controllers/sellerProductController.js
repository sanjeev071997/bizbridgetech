import mongoose from "mongoose";
import Product from "../models/sellerProductModel.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import Errorhandler from "../utils/Errorhandler.js";
import cloudinary from "../utils/cloudinary.js";
import BuyerCategory from "../models/buyerCategoriesModel.js";
import SellerCategory from "../models/sellercategoriesModel.js";

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
  const { name, image, mrp, unit, category, description, specifications } =
    req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    // VALIDATION: Category must be provided
    if (!category) {
      return next(new Errorhandler("Product category is required.", 400));
    }

    // VALIDATION: Category must exist in DB
    const productCategory = await SellerCategory.findById(category);
    if (!productCategory) {
      return next(
        new Errorhandler(
          "Invalid product category. Please select a valid category.",
          404
        )
      );
    }

    // CASE 1️ : Base64 IMAGE
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    }

    // CASE 2: CLOUDINARY UPLOAD (normal file path)
    else if (image && !image.startsWith("http")) {
      const result = await cloudinary.uploader.upload(image, {
        folder: "SallerProducts",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    // CASE 3: DIRECT IMAGE URL (no Cloudinary upload)
    else if (image && image.startsWith("http")) {
      imageUrl = image; // directly use URL
      cloudinaryId = ""; // No Cloudinary upload
    }

    // NO IMAGE
    // if (!imageUrl) {
    //   return next(new Errorhandler("Image not provided or invalid", 400));
    // }

    // Create Product
    const newProduct = await Product.create({
      user: req.user._id,
      name,
      image: imageUrl,
      cloudinaryId,
      mrp,
      unit,
      category,
      // stock,
      description,
      specifications,
    });

    res.status(200).json({
      success: true,
      message: "Product added successfully",
      product: newProduct,
    });
  } catch (error) {
    return next(
      new Errorhandler("Error processing product upload or creation", 500)
    );
  }
});

// Update product discount & visible
// export const updateProductCategoryAndVisibility = catchAsyncErrors(
//   async (req, res, next) => {
//     const { buyerCategory, visible, productId } = req.body;

//     try {
//       // Validate productId
//       if (!mongoose.Types.ObjectId.isValid(productId)) {
//         return next(new Errorhandler("Invalid product ID", 400));
//       }

//       // Fetch product
//       const product = await Product.findById(productId);
//       if (!product) {
//         return next(new Errorhandler("Product not found", 404));
//       }

//       // Validate buyerCategory
//       if (!mongoose.Types.ObjectId.isValid(buyerCategory)) {
//         return next(new Errorhandler("Invalid buyerCategory ID", 400));
//       }

//       // Fetch buyerCategory data
//       const buyerCatData = await BuyerCategory.findById(buyerCategory).select(
//         "discount"
//       );
//       if (!buyerCatData) {
//         return next(new Errorhandler("BuyerCategory not found", 404));
//       }

//       // Initialize productVisibility if missing
//       if (!product.productVisibility) product.productVisibility = [];

//       // Remove invalid entries (buyerCategory: null)
//       product.productVisibility = product.productVisibility.filter(
//         (v) => v.buyerCategory
//       );

//       // Check if visibility for this buyerCategory already exists
//       const existingVisibility = product.productVisibility.find(
//         (v) => v.buyerCategory.toString() === buyerCategory.toString()
//       );

//       if (existingVisibility) {
//         existingVisibility.visible = visible;
//       } else {
//         product.productVisibility.push({
//           buyerCategory,
//           visible,
//         });
//       }

//       // Calculate price based on discount
//       let price = product.mrp;
//       if (buyerCatData.discount && buyerCatData.discount > 0) {
//         price = product.mrp - (product.mrp * buyerCatData.discount) / 100;
//       }
//       product.price = price;

//       // Save product
//       await product.save();

//       res.status(200).json({
//         success: true,
//         message: "Product updated successfully for buyerCategory visibility",
//         product,
//       });
//     } catch (error) {
//       console.error("Error updating product:", error);
//       return next(new Errorhandler("Error updating product", 500));
//     }
//   }
// );

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
      return next(
        new Errorhandler("You are not authorized to delete this product", 403)
      );
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

// Function to update a product
// export const updateProduct = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;
//   const {
//     image,
//     name,
//     category,
//     mrp,
//     unit,
//     // stock,
//     description,
//     specifications,
//     buyerCategory,
//     price,
//   } = req.body;

//   try {
//     const product = await Product.findById(id).populate(
//       "productVisibility.buyerCategory",
//       "name discount"
//     );
//     if (!product) {
//       return next(new Errorhandler("Product not found", 404));
//     }

//     // Permission check
//     if (
//       product.user.toString() !== req.user._id.toString() &&
//       req.user.role !== 1
//     ) {
//       return next(
//         new Errorhandler("You are not authorized to update this product", 403)
//       );
//     }

//     // Handle image update
//     let imageUrl = product.image;
//     let cloudinaryId = product.cloudinaryId;
//     if (image && image.startsWith("data:image")) {
//       if (product.cloudinaryId) {
//         await cloudinary.uploader.destroy(product.cloudinaryId);
//       }
//       const result = await uploadBase64Image(image);
//       imageUrl = result.image;
//       cloudinaryId = result.cloudinaryId;
//     } else if (image && image !== product.image) {
//       if (product.cloudinaryId) {
//         await cloudinary.uploader.destroy(product.cloudinaryId);
//       }
//       const result = await cloudinary.uploader.upload(image, {
//         folder: "SallerProducts",
//       });
//       imageUrl = result.secure_url;
//       cloudinaryId = result.public_id;
//     }

//     // Update base product fields
//     const oldMrp = product.mrp;
//     product.name = name || product.name;
//     product.unit = unit || product.unit;
//     product.image = imageUrl;
//     product.cloudinaryId = cloudinaryId;
//     product.mrp = mrp || product.mrp;
//     product.category = category || product.category;
//     // product.stock = stock || product.stock;
//     product.description = description || product.description;
//     product.specifications = specifications || product.specifications;

//     // Agar buyerCategory diya gaya hai to add/update
//     if (buyerCategory) {
//       const buyerCategoryDoc = await BuyerCategory.findById(buyerCategory);
//       if (!buyerCategoryDoc) {
//         return next(new Errorhandler("Buyer category not found", 404));
//       }

//       const discount = parseFloat(buyerCategoryDoc.discount) || 0;
//       let finalPrice = mrp
//         ? mrp - (mrp * discount) / 100
//         : product.mrp - (product.mrp * discount) / 100;

//       // agar price explicitly diya hai to override
//       if (price) {
//         finalPrice = price;
//       }

//       const alreadyExists = product.productVisibility.find(
//         (v) =>
//           v.buyerCategory &&
//           v.buyerCategory._id.toString() === buyerCategoryDoc._id.toString()
//       );

//       if (!alreadyExists) {
//         product.productVisibility.push({
//           buyerCategory: buyerCategoryDoc._id,
//           visible: true,
//           price: finalPrice,
//         });
//       } else {
//         alreadyExists.price = finalPrice;
//         alreadyExists.visible = true;
//       }
//     }

//     if (mrp && mrp !== oldMrp) {
//       for (let visibility of product.productVisibility) {
//         if (
//           visibility.buyerCategory &&
//           visibility.buyerCategory.discount != null
//         ) {
//           const discount = parseFloat(visibility.buyerCategory.discount) || 0;
//           visibility.price = mrp - (mrp * discount) / 100;
//         }
//       }
//     }

//     const updatedProduct = await product.save();

//     await updatedProduct.populate(
//       "productVisibility.buyerCategory",
//       "name discount"
//     );

//     res.status(200).json({
//       success: true,
//       message: "Product updated successfully",
//       updatedProduct,
//     });
//   } catch (error) {
//     console.log(error);
//     return next(new Errorhandler("Error updating product", 500));
//   }
// });

// Function to get a product by ID for Seller own products
// export const getProductByUserId = catchAsyncErrors(async (req, res, next) => {
//   const user = req.user.id;

//   // ✅ Pagination params
//   const page = parseInt(req.query.page) || 1;
//   const limit = parseInt(req.query.limit) || 10;
//   const skip = (page - 1) * limit;

//   try {
//     // ✅ Total count (for frontend pagination)
//     const totalProducts = await Product.countDocuments({ user });

//     const products = await Product.find({ user })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .populate({
//         path: "productVisibility.buyerCategory",
//         select: "name discount",
//       })
//       .sort({ createdAt: -1 })
//       .skip(skip)
//       .limit(limit);

//     if (!products || products.length === 0) {
//       return next(new Errorhandler("Product not found", 404));
//     }

//     // 🔁 Price recalculation logic
//     for (const product of products) {
//       let hasChanges = false;

//       product.productVisibility = product.productVisibility.map((vis) => {
//         if (!vis.buyerCategory) return vis;

//         const discount = Number(vis.buyerCategory.discount) || 0;
//         const mrp = Number(product.mrp) || 0;
//         const calculatedPrice = Math.round(
//           mrp - (mrp * discount) / 100
//         );

//         if (vis.price !== calculatedPrice) {
//           vis.price = calculatedPrice;
//           hasChanges = true;
//         }

//         vis.appliedDiscount = discount;
//         return vis;
//       });

//       if (hasChanges) {
//         await Product.updateOne(
//           { _id: product._id },
//           { $set: { productVisibility: product.productVisibility } }
//         );
//       }
//     }

//     res.status(200).json({
//       success: true,
//       product: products,
//       pagination: {
//         totalProducts,
//         currentPage: page,
//         totalPages: Math.ceil(totalProducts / limit),
//         limit,
//       },
//     });
//   } catch (error) {
//     return next(new Errorhandler("Error fetching product", 500));
//   }
// });

// Function to get a products for Buyer view with discount & visibility logic
export const getBuyerProducts = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode; // "buyer" or "seller"

    let connections;

    if (mode === "buyer") {
      connections = await BuyerSellerConnection.find({
        buyer: userId,
        status: "Accepted",
      }).populate("buyerCategory", "name discount");
    } else if (mode === "seller") {
      connections = await BuyerSellerConnection.find({
        seller: userId,
        status: "Accepted",
      }).populate("buyerCategory", "name discount");
    } else {
      return res.status(400).json({
        success: false,
        message: "Invalid user mode",
      });
    }

    if (!connections || connections.length === 0) {
      return res.status(200).json({
        success: true,
        products: [],
        message: "No accepted connections found for this user",
      });
    }

    // Step 2: Prepare category–seller–discount mapping
    const filterPairs = connections.map((conn) => ({
      buyerCategoryId: conn.buyerCategory._id.toString(),
      discount: parseFloat(conn.buyerCategory.discount) || 0,
      sellerId: conn.seller.toString(),
      buyerId: conn.buyer.toString(),
    }));

    // Step 3: Fetch products for all connected sellers
    const products = await Product.find({
      user: { $in: filterPairs.map((p) => p.sellerId) },
      productVisibility: { $exists: true, $ne: [] },
    })
      .populate("category", "name gst")
      .populate("user", "name phone email businessName businessAddress")
      .populate("productVisibility.buyerCategory", "name discount")
      .sort({ createdAt: -1 })
      .lean();

    const finalProducts = [];

    // Step 4: Filter each product based on connection buyerCategory
    for (const product of products) {
      for (const pair of filterPairs) {
        const matchedVis = product.productVisibility.find((v) => {
          if (!v.buyerCategory) return false;
          const catId =
            typeof v.buyerCategory === "object"
              ? v.buyerCategory._id?.toString()
              : v.buyerCategory?.toString();
          return catId === pair.buyerCategoryId && v.visible === true;
        });

        if (
          mode === "buyer" &&
          product.user._id.toString() === pair.sellerId &&
          matchedVis
        ) {
          // Only include the matched buyerCategory visibility
          const filteredVisibility = [matchedVis];

          finalProducts.push({
            ...product,
            productVisibility: filteredVisibility,
            appliedDiscount: pair.discount,
            finalPrice: matchedVis.price || product.mrp,
          });
          break;
        }

        if (
          mode === "seller" &&
          product.user._id.toString() === userId.toString() &&
          matchedVis
        ) {
          // Seller mode → can see all buyer visibilities (unchanged)
          finalProducts.push({
            ...product,
            appliedDiscount: pair.discount,
            finalPrice: matchedVis.price || product.mrp,
          });
          break;
        }
      }
    }

    if (finalProducts.length === 0) {
      return res.status(200).json({
        success: true,
        products: [],
        message: "No products available for your category at the moment",
      });
    }

    res.status(200).json({
      success: true,
      products: finalProducts,
    });
  } catch (error) {
    console.error(error);
    return next(new Errorhandler("Error fetching products", 500));
  }
});

// Get Buyer Category Products
// export const getProductsByBuyerCategoryId = catchAsyncErrors(
//   async (req, res, next) => {
//     const { buyerCategory } = req.params;
//     const loginUserId = req.user?._id;

//     // ✅ Pagination params
//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;
//     const skip = (page - 1) * limit;

//     if (!mongoose.Types.ObjectId.isValid(buyerCategory)) {
//       return next(new Errorhandler("Invalid buyer category ID", 400));
//     }

//     try {
//       const buyerCategoryDoc = await BuyerCategory.findById(buyerCategory);
//       if (!buyerCategoryDoc) {
//         return next(new Errorhandler("Buyer category not found", 404));
//       }

//       const discount = parseFloat(buyerCategoryDoc.discount) || 0;
//       const buyerCatOid = new mongoose.Types.ObjectId(buyerCategory);

//       // ✅ Total count (for pagination)
//       const totalProducts = await Product.countDocuments({
//         user: loginUserId,
//       });

//       // ✅ Fetch paginated products
//       const products = await Product.find({ user: loginUserId })
//         .sort({ createdAt: -1 })
//         .select("_id mrp name image unit productVisibility category")
//         .skip(skip)
//         .limit(limit)
//         .lean();

//       if (!products.length) {
//         return next(new Errorhandler("No products found", 404));
//       }

//       const bulkOps = [];

//       for (const p of products) {
//         const vis = p.productVisibility || [];

//         const exists = vis.some((v) => {
//           const catId =
//             v?.buyerCategory?._id
//               ? v.buyerCategory._id.toString()
//               : v?.buyerCategory?.toString?.();
//           return catId === buyerCategory;
//         });

//         if (!exists) {
//           const priceAfterDiscount =
//             discount > 0 ? p.mrp - (p.mrp * discount) / 100 : p.mrp;

//           bulkOps.push({
//             updateOne: {
//               filter: {
//                 _id: p._id,
//                 "productVisibility.buyerCategory": { $ne: buyerCatOid },
//               },
//               update: {
//                 $push: {
//                   productVisibility: {
//                     buyerCategory: buyerCatOid,
//                     visible: true,
//                     price: priceAfterDiscount,
//                   },
//                 },
//               },
//             },
//           });
//         }
//       }

//       if (bulkOps.length > 0) {
//         await Product.bulkWrite(bulkOps);
//       }

//       // ✅ Re-fetch only paginated products
//       const updatedProducts = await Product.find({
//         _id: { $in: products.map((p) => p._id) },
//       })
//         .populate("productVisibility.buyerCategory", "name discount")
//         .populate("category", "name gst")
//         .sort({ createdAt: -1 });

//       const filteredProducts = updatedProducts.map((product) => {
//         const matched = product.productVisibility.find((v) => {
//           const catId =
//             v.buyerCategory && v.buyerCategory._id
//               ? v.buyerCategory._id.toString()
//               : v.buyerCategory?.toString?.();
//           return catId === buyerCategory;
//         });

//         return {
//           _id: product._id,
//           name: product.name,
//           unit: product.unit,
//           mrp: product.mrp,
//           image: product.image,
//           category: product.category,
//           buyerCategory: matched
//             ? {
//                 id: matched.buyerCategory._id,
//                 name: matched.buyerCategory.name,
//                 discount: matched.buyerCategory.discount,
//                 price: matched.price,
//                 visible: matched.visible,
//               }
//             : {
//                 id: buyerCategoryDoc._id,
//                 name: buyerCategoryDoc.name,
//                 discount: buyerCategoryDoc.discount,
//                 price: product.mrp,
//                 visible: buyerCategoryDoc.defaultVisibility || false,
//               },
//         };
//       });

//       return res.status(200).json({
//         success: true,
//         products: filteredProducts,
//         pagination: {
//           totalProducts,
//           currentPage: page,
//           totalPages: Math.ceil(totalProducts / limit),
//           limit,
//         },
//       });
//     } catch (error) {
//       console.error("Detailed Error:", error);
//       return next(
//         new Errorhandler("Error fetching products by buyer category", 500)
//       );
//     }
//   }
// );

// Get Products by Connection (new function)
export const getProductsByConnection = async (req, res, next) => {
  try {
    const { connectionId, otherUserId } = req.body;

    if (!connectionId || !otherUserId) {
      return res.status(400).json({
        success: false,
        message: "connectionId and otherUserId are required",
      });
    }

    const connection = await BuyerSellerConnection.findById(connectionId);
    if (!connection) {
      return res.status(404).json({
        success: false,
        message: "Connection not found",
      });
    }

    if (connection.status !== "Accepted") {
      return res.status(403).json({
        success: false,
        message: "Connection is not accepted yet",
      });
    }

    // Determine buyer/seller based on req.user.mode
    let sellerId;
    let buyerId;
    if (req.user.mode === "buyer") {
      buyerId = req.user._id;
      sellerId = otherUserId;
    } else if (req.user.mode === "seller") {
      sellerId = req.user._id;
      buyerId = otherUserId;
    } else {
      return res.status(400).json({
        success: false,
        message: "Invalid user mode",
      });
    }

    const buyerCategory = connection.buyerCategory;

    // Fetch seller products
    const products = await Product.find({ user: sellerId })
      .populate(
        "user",
        "name phone email businessName businessAddress createdAt"
      )
      .populate(
        "category",
        "name"
      )
      .sort({ createdAt: -1 });

    // Filter products by matching buyerCategory in productVisibility
    const filteredProducts = products
      .map((product) => {
        if (
          !product.productVisibility ||
          product.productVisibility.length === 0
        )
          return null;

        const matchingVisibility = product.productVisibility.find(
          (pv) =>
            pv &&
            pv.buyerCategory &&
            pv.buyerCategory.toString() === buyerCategory.toString() &&
            pv.visible === true
        );

        if (!matchingVisibility) return null;

        // Return product with only the matching productVisibility entry
        return {
          ...product.toObject(),
          productVisibility: [matchingVisibility],
          price: matchingVisibility.price, // optional: override product-level price
        };
      })
      .filter(Boolean); // remove nulls

    return res.status(200).json({
      success: true,
      message: "Products fetched successfully",
      buyerCategory,
      totalProducts: filteredProducts.length,
      data: filteredProducts,
    });
  } catch (error) {
    return next(new Errorhandler("Error fetching products", 500));
  }
};

// Function to get all products Admin view
export const getAllProducts = catchAsyncErrors(async (req, res, next) => {
  try {
    let { page = 1, limit = 10 } = req.query;
    page = parseInt(page, 10);
    limit = parseInt(limit, 10);
    const skip = (page - 1) * limit;
    let query = Product.find()
      .populate("category", "name gst")
      .populate("user", "name phone businessName")
      .populate({
        path: "productVisibility.buyerCategory",
        select: "name discount",
      })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Conditionally populate user details if role === 1 (superadmin)
    if (req.user.role === 1) {
      query = query.populate("user", "name phone businessName");
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

// Toggle All Product hide
export const toggleProductsVisibilityByBuyerCategory = catchAsyncErrors(
  async (req, res, next) => {
    const { buyerCategoryId, productCategoryId } = req.body;
    const user = req.user._id;

    // Validate both IDs
    if (!mongoose.Types.ObjectId.isValid(buyerCategoryId)) {
      return next(new Errorhandler("Invalid buyerCategory ID", 400));
    }

    if (!mongoose.Types.ObjectId.isValid(productCategoryId)) {
      return next(new Errorhandler("Invalid productCategory ID", 400));
    }

    try {
      let query = {
        "productVisibility.buyerCategory": buyerCategoryId,
        category: productCategoryId,  
        user
      };
      const products = await Product.find(query);
      if (!products.length) {
        return res.status(404).json({
          success: false,
          message: `No products found for buyer category: ${buyerCategoryId} and product category: ${productCategoryId}`,
        });
      }

      // Check current visibility status
      let anyVisible = false;
      
      products.forEach((product) => {
        product.productVisibility.forEach((v) => {
          if (
            v.buyerCategory &&
            v.buyerCategory.toString() === buyerCategoryId.toString() &&
            v.visible === true
          ) {
            anyVisible = true;
          }
        });
      });

      const newVisibility = !anyVisible;
      let updatedCount = 0;

      // Update each product's visibility
      for (const product of products) {
        let updated = false;

        product.productVisibility = product.productVisibility.filter(
          (v) => v.buyerCategory
        );

        let visibilityEntry = product.productVisibility.find(
          (v) => v.buyerCategory.toString() === buyerCategoryId.toString()
        );

        if (visibilityEntry) {
          visibilityEntry.visible = newVisibility;
          updated = true;
        } else {
          product.productVisibility.push({
            buyerCategory: buyerCategoryId,
            visible: newVisibility
          });
          updated = true;
        }

        if (updated) {
          await product.save();
          updatedCount++;
        }
      }

      res.status(200).json({
        success: true,
        message: `Products visibility set to ${newVisibility} for selected categories`,
        newVisibility,
        totalProductsUpdated: updatedCount,
        buyerCategoryId,
        productCategoryId
      });
    } catch (error) {
      console.error("Toggle visibility error:", error);
      return next(new Errorhandler("Error toggling visibility", 500));
    }
  }
);



// New Apis IN APIS ME AGR MRP CHANGE HO RHI HAI TO CUSTOM PRICE change nhi hoge 
// Function to update a product
export const updateProduct = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const {
    image,
    name,
    category,
    mrp,
    unit,
    description,
    specifications,
    // buyerCategory और price को हटा दें - ये edit product में नहीं भेजेंगे
  } = req.body;

  try {
    const product = await Product.findById(id).populate(
      "productVisibility.buyerCategory",
      "name discount"
    );
    if (!product) {
      return next(new Errorhandler("Product not found", 404));
    }

    // Permission check
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
      if (product.cloudinaryId) {
        await cloudinary.uploader.destroy(product.cloudinaryId);
      }
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    } else if (image && image !== product.image) {
      if (product.cloudinaryId) {
        await cloudinary.uploader.destroy(product.cloudinaryId);
      }
      const result = await cloudinary.uploader.upload(image, {
        folder: "SallerProducts",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    // Update base product fields
    const oldMrp = product.mrp;
    product.name = name || product.name;
    product.unit = unit || product.unit;
    product.image = imageUrl;
    product.cloudinaryId = cloudinaryId;
    product.mrp = mrp || product.mrp;
    product.category = category || product.category;
    product.description = description || product.description;
    product.specifications = specifications || product.specifications;

    // MRP change होने पर केवल उन्हीं buyer categories की price update करें 
    // जिनकी price manually set नहीं है
    if (mrp && mrp !== oldMrp) {
      for (let visibility of product.productVisibility) {
        if (
          visibility.buyerCategory &&
          visibility.buyerCategory.discount != null &&
          !visibility.isPriceManuallySet  // Only update if price wasn't manually set
        ) {
          const discount = parseFloat(visibility.buyerCategory.discount) || 0;
          visibility.price = mrp - (mrp * discount) / 100;
        }
      }
    }

    const updatedProduct = await product.save();

    await updatedProduct.populate(
      "productVisibility.buyerCategory",
      "name discount"
    );

    res.status(200).json({
      success: true,
      message: "Product updated successfully",
      updatedProduct,
    });
  } catch (error) {
    console.log(error);
    return next(new Errorhandler("Error updating product", 500));
  }
});

// Update product discount & visible - WITH PRICE UPDATE SUPPORT
export const updateProductCategoryAndVisibility = catchAsyncErrors(
  async (req, res, next) => {
    const { buyerCategory, visible, productId, price: userPrice } = req.body;

    console.log("Price Change API Called:", { 
      buyerCategory, 
      productId, 
      userPrice,
      visible 
    });

    try {
      // Validate productId
      if (!mongoose.Types.ObjectId.isValid(productId)) {
        return next(new Errorhandler("Invalid product ID", 400));
      }

      // Fetch product
      const product = await Product.findById(productId);
      if (!product) {
        return next(new Errorhandler("Product not found", 404));
      }

      // Validate buyerCategory
      if (!mongoose.Types.ObjectId.isValid(buyerCategory)) {
        return next(new Errorhandler("Invalid buyerCategory ID", 400));
      }

      // Fetch buyerCategory data
      const buyerCatData = await BuyerCategory.findById(buyerCategory).select(
        "discount"
      );
      if (!buyerCatData) {
        return next(new Errorhandler("BuyerCategory not found", 404));
      }

      // Initialize productVisibility if missing
      if (!product.productVisibility) product.productVisibility = [];

      // Remove invalid entries (buyerCategory: null)
      product.productVisibility = product.productVisibility.filter(
        (v) => v.buyerCategory
      );

      // Check if visibility for this buyerCategory already exists
      const existingVisibility = product.productVisibility.find(
        (v) => v.buyerCategory.toString() === buyerCategory.toString()
      );

      if (existingVisibility) {
        // Update visibility status
        existingVisibility.visible = visible !== undefined ? visible : existingVisibility.visible;
        
        // Update price if user provided
        if (userPrice !== undefined && userPrice !== null && userPrice !== "") {
          const newPrice = parseFloat(userPrice);
          if (!isNaN(newPrice) && newPrice > 0) {
            existingVisibility.price = newPrice;
            existingVisibility.isPriceManuallySet = true;  // Mark as manually set
            existingVisibility.lastPriceUpdate = new Date();
            console.log("Updated price to:", newPrice, "Manually set: true");
          }
        }
      } else {
        // For new visibility entry
        let finalPrice = product.mrp; // Default to MRP
        
        // If user has provided a price, use that
        if (userPrice !== undefined && userPrice !== null && userPrice !== "") {
          const newPrice = parseFloat(userPrice);
          if (!isNaN(newPrice) && newPrice > 0) {
            finalPrice = newPrice;
          }
        } 
        // Otherwise calculate based on discount for new entries
        else if (buyerCatData.discount && buyerCatData.discount > 0) {
          finalPrice = product.mrp - (product.mrp * buyerCatData.discount) / 100;
        }
        
        console.log("Setting new price:", finalPrice, "Manually set:", userPrice !== undefined);
        
        product.productVisibility.push({
          buyerCategory,
          visible: visible !== undefined ? visible : true,
          price: finalPrice,
          isPriceManuallySet: (userPrice !== undefined && userPrice !== null && userPrice !== ""), // Mark if custom
          lastPriceUpdate: new Date()
        });
      }

      // Save product
      await product.save();
      console.log("Product saved successfully with updated price");

      res.status(200).json({
        success: true,
        message: "Product updated successfully",
        product,
      });
    } catch (error) {
      console.error("Error updating product:", error);
      return next(new Errorhandler("Error updating product", 500));
    }
  }
);

// Get Buyer Category Products - WITH MANUAL PRICE SUPPORT
export const getProductsByBuyerCategoryId = catchAsyncErrors(
  async (req, res, next) => {
    const { buyerCategory } = req.params;
    const loginUserId = req.user?._id;

    // ✅ Pagination params
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    if (!mongoose.Types.ObjectId.isValid(buyerCategory)) {
      return next(new Errorhandler("Invalid buyer category ID", 400));
    }

    try {
      const buyerCategoryDoc = await BuyerCategory.findById(buyerCategory);
      if (!buyerCategoryDoc) {
        return next(new Errorhandler("Buyer category not found", 404));
      }

      const discount = parseFloat(buyerCategoryDoc.discount) || 0;
      const buyerCatOid = new mongoose.Types.ObjectId(buyerCategory);

      // ✅ Total count (for pagination)
      const totalProducts = await Product.countDocuments({
        user: loginUserId,
      });

      // ✅ Fetch paginated products
      const products = await Product.find({ user: loginUserId })
        .sort({ createdAt: -1 })
        .select("_id mrp name image unit productVisibility category")
        .skip(skip)
        .limit(limit)
        .lean();

      if (!products.length) {
        return next(new Errorhandler("No products found", 404));
      }

      const bulkOps = [];

      for (const p of products) {
        const vis = p.productVisibility || [];

        const exists = vis.some((v) => {
          const catId =
            v?.buyerCategory?._id
              ? v.buyerCategory._id.toString()
              : v?.buyerCategory?.toString?.();
          return catId === buyerCategory;
        });

        if (!exists) {
          const priceAfterDiscount =
            discount > 0 ? p.mrp - (p.mrp * discount) / 100 : p.mrp;

          bulkOps.push({
            updateOne: {
              filter: {
                _id: p._id,
                "productVisibility.buyerCategory": { $ne: buyerCatOid },
              },
              update: {
                $push: {
                  productVisibility: {
                    buyerCategory: buyerCatOid,
                    visible: true,
                    price: priceAfterDiscount,
                    isPriceManuallySet: false,  // Default to false for auto-calculated
                  },
                },
              },
            },
          });
        }
      }

      if (bulkOps.length > 0) {
        await Product.bulkWrite(bulkOps);
      }

      // ✅ Re-fetch only paginated products
      const updatedProducts = await Product.find({
        _id: { $in: products.map((p) => p._id) },
      })
        .populate("productVisibility.buyerCategory", "name discount")
        .populate("category", "name gst")
        .sort({ createdAt: -1 });

      const filteredProducts = updatedProducts.map((product) => {
        const matched = product.productVisibility.find((v) => {
          const catId =
            v.buyerCategory && v.buyerCategory._id
              ? v.buyerCategory._id.toString()
              : v.buyerCategory?.toString?.();
          return catId === buyerCategory;
        });

        let displayPrice = product.mrp; // Default
        let isCustomPrice = false;
        
        if (matched) {
          // Use manually set price if exists, otherwise calculate
          if (matched.isPriceManuallySet) {
            displayPrice = matched.price;
            isCustomPrice = true;
          } else {
            const discountVal = matched.buyerCategory?.discount || 0;
            displayPrice = product.mrp - (product.mrp * discountVal) / 100;
          }
        } else {
          // No visibility entry yet, calculate based on buyer category discount
          displayPrice = discount > 0 ? product.mrp - (product.mrp * discount) / 100 : product.mrp;
        }

        return {
          _id: product._id,
          name: product.name,
          unit: product.unit,
          mrp: product.mrp,
          image: product.image,
          category: product.category,
          price: displayPrice,  // This will be the correct price
          buyerCategory: matched
            ? {
                id: matched.buyerCategory._id,
                name: matched.buyerCategory.name,
                discount: matched.buyerCategory.discount,
                price: displayPrice,
                visible: matched.visible,
                isPriceManuallySet: matched.isPriceManuallySet || false,
              }
            : {
                id: buyerCategoryDoc._id,
                name: buyerCategoryDoc.name,
                discount: buyerCategoryDoc.discount,
                price: displayPrice,
                visible: buyerCategoryDoc.defaultVisibility || false,
                isPriceManuallySet: false,
              },
        };
      });

      return res.status(200).json({
        success: true,
        products: filteredProducts,
        pagination: {
          totalProducts,
          currentPage: page,
          totalPages: Math.ceil(totalProducts / limit),
          limit,
        },
      });
    } catch (error) {
      console.error("Detailed Error:", error);
      return next(
        new Errorhandler("Error fetching products by buyer category", 500)
      );
    }
  }
);

// Function to get a product by ID for Seller own products
export const getProductByUserId = catchAsyncErrors(async (req, res, next) => {
  const user = req.user.id;

  // ✅ Pagination params
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  try {
    // ✅ Total count (for frontend pagination)
    const totalProducts = await Product.countDocuments({ user });

    const products = await Product.find({ user })
      .populate("category", "name gst")
      .populate("user", "name phone businessName")
      .populate({
        path: "productVisibility.buyerCategory",
        select: "name discount",
      })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    if (!products || products.length === 0) {
      return next(new Errorhandler("Product not found", 404));
    }

    // 🔁 Price recalculation logic - ONLY for non-manually set prices
    for (const product of products) {
      let hasChanges = false;

      product.productVisibility = product.productVisibility.map((vis) => {
        if (!vis.buyerCategory) return vis;

        // Skip if price was manually set
        if (vis.isPriceManuallySet) {
          return vis;
        }

        const discount = Number(vis.buyerCategory.discount) || 0;
        const mrp = Number(product.mrp) || 0;
        const calculatedPrice = Math.round(mrp - (mrp * discount) / 100);

        if (vis.price !== calculatedPrice) {
          vis.price = calculatedPrice;
          hasChanges = true;
        }

        vis.appliedDiscount = discount;
        return vis;
      });

      if (hasChanges) {
        await Product.updateOne(
          { _id: product._id },
          { $set: { productVisibility: product.productVisibility } }
        );
      }
    }

    res.status(200).json({
      success: true,
      product: products,
      pagination: {
        totalProducts,
        currentPage: page,
        totalPages: Math.ceil(totalProducts / limit),
        limit,
      },
    });
  } catch (error) {
    return next(new Errorhandler("Error fetching product", 500));
  }
});

// New Apis IN APIS ME AGR MRP CHANGE HO RHI HAI TO CUSTOM PRICE bhi change hoge 
// Function to update a product - ALL PRICES UPDATE WITH MRP CHANGE
// export const updateProduct = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;
//   const {
//     image,
//     name,
//     category,
//     mrp,
//     unit,
//     description,
//     specifications,
//   } = req.body;

//   try {
//     const product = await Product.findById(id).populate(
//       "productVisibility.buyerCategory",
//       "name discount"
//     );
//     if (!product) {
//       return next(new Errorhandler("Product not found", 404));
//     }

//     // Permission check
//     if (
//       product.user.toString() !== req.user._id.toString() &&
//       req.user.role !== 1
//     ) {
//       return next(
//         new Errorhandler("You are not authorized to update this product", 403)
//       );
//     }

//     // Handle image update
//     let imageUrl = product.image;
//     let cloudinaryId = product.cloudinaryId;
//     if (image && image.startsWith("data:image")) {
//       if (product.cloudinaryId) {
//         await cloudinary.uploader.destroy(product.cloudinaryId);
//       }
//       const result = await uploadBase64Image(image);
//       imageUrl = result.image;
//       cloudinaryId = result.cloudinaryId;
//     } else if (image && image !== product.image) {
//       if (product.cloudinaryId) {
//         await cloudinary.uploader.destroy(product.cloudinaryId);
//       }
//       const result = await cloudinary.uploader.upload(image, {
//         folder: "SallerProducts",
//       });
//       imageUrl = result.secure_url;
//       cloudinaryId = result.public_id;
//     }

//     // Update base product fields
//     const oldMrp = product.mrp;
//     const newMrp = mrp || product.mrp;
    
//     product.name = name || product.name;
//     product.unit = unit || product.unit;
//     product.image = imageUrl;
//     product.cloudinaryId = cloudinaryId;
//     product.mrp = newMrp;
//     product.category = category || product.category;
//     product.description = description || product.description;
//     product.specifications = specifications || product.specifications;

//     // ✅ IMPORTANT: MRP change होने पर सभी buyer categories की price update करें
//     if (newMrp !== oldMrp) {
//       console.log(`MRP changed from ${oldMrp} to ${newMrp}. Updating all buyer category prices...`);
      
//       for (let visibility of product.productVisibility) {
//         if (visibility.buyerCategory && visibility.buyerCategory.discount != null) {
//           const discount = parseFloat(visibility.buyerCategory.discount) || 0;
          
//           // Calculate new price based on new MRP and discount
//           const newPrice = newMrp - (newMrp * discount) / 100;
          
//           // Update the price
//           visibility.price = newPrice;
          
//           // Mark as NOT manually set (since it's auto-calculated from MRP change)
//           visibility.isPriceManuallySet = false;
          
//           console.log(`Updated price for buyer category ${visibility.buyerCategory.name}: ${newPrice}`);
//         }
//       }
//     }

//     const updatedProduct = await product.save();

//     await updatedProduct.populate(
//       "productVisibility.buyerCategory",
//       "name discount"
//     );

//     res.status(200).json({
//       success: true,
//       message: "Product updated successfully",
//       updatedProduct,
//     });
//   } catch (error) {
//     console.log(error);
//     return next(new Errorhandler("Error updating product", 500));
//   }
// });

// // Update product discount & visible - WITH PRICE UPDATE SUPPORT
// export const updateProductCategoryAndVisibility = catchAsyncErrors(
//   async (req, res, next) => {
//     const { buyerCategory, visible, productId, price: userPrice } = req.body;

//     console.log("Price Change API Called:", { 
//       buyerCategory, 
//       productId, 
//       userPrice,
//       visible 
//     });

//     try {
//       // Validate productId
//       if (!mongoose.Types.ObjectId.isValid(productId)) {
//         return next(new Errorhandler("Invalid product ID", 400));
//       }

//       // Fetch product
//       const product = await Product.findById(productId);
//       if (!product) {
//         return next(new Errorhandler("Product not found", 404));
//       }

//       // Validate buyerCategory
//       if (!mongoose.Types.ObjectId.isValid(buyerCategory)) {
//         return next(new Errorhandler("Invalid buyerCategory ID", 400));
//       }

//       // Fetch buyerCategory data
//       const buyerCatData = await BuyerCategory.findById(buyerCategory).select(
//         "discount"
//       );
//       if (!buyerCatData) {
//         return next(new Errorhandler("BuyerCategory not found", 404));
//       }

//       // Initialize productVisibility if missing
//       if (!product.productVisibility) product.productVisibility = [];

//       // Remove invalid entries (buyerCategory: null)
//       product.productVisibility = product.productVisibility.filter(
//         (v) => v.buyerCategory
//       );

//       // Check if visibility for this buyerCategory already exists
//       const existingVisibility = product.productVisibility.find(
//         (v) => v.buyerCategory.toString() === buyerCategory.toString()
//       );

//       if (existingVisibility) {
//         // Update visibility status
//         existingVisibility.visible = visible !== undefined ? visible : existingVisibility.visible;
        
//         // Update price if user provided
//         if (userPrice !== undefined && userPrice !== null && userPrice !== "") {
//           const newPrice = parseFloat(userPrice);
//           if (!isNaN(newPrice) && newPrice > 0) {
//             existingVisibility.price = newPrice;
//             existingVisibility.isPriceManuallySet = true;  // Mark as manually set
//             existingVisibility.lastPriceUpdate = new Date();
//             console.log("Manually updated price to:", newPrice);
//           }
//         } else {
//           // If user didn't provide price but we need to update based on discount
//           const discount = parseFloat(buyerCatData.discount) || 0;
//           const calculatedPrice = product.mrp - (product.mrp * discount) / 100;
//           existingVisibility.price = calculatedPrice;
//           existingVisibility.isPriceManuallySet = false; // Auto-calculated
//           console.log("Auto-calculated price:", calculatedPrice, "based on discount:", discount);
//         }
//       } else {
//         // For new visibility entry
//         let finalPrice = product.mrp; // Default to MRP
        
//         // If user has provided a price, use that
//         if (userPrice !== undefined && userPrice !== null && userPrice !== "") {
//           const newPrice = parseFloat(userPrice);
//           if (!isNaN(newPrice) && newPrice > 0) {
//             finalPrice = newPrice;
//           }
//         } 
//         // Otherwise calculate based on discount for new entries
//         else if (buyerCatData.discount && buyerCatData.discount > 0) {
//           finalPrice = product.mrp - (product.mrp * buyerCatData.discount) / 100;
//         }
        
//         console.log("Setting new price:", finalPrice);
        
//         product.productVisibility.push({
//           buyerCategory,
//           visible: visible !== undefined ? visible : true,
//           price: finalPrice,
//           isPriceManuallySet: (userPrice !== undefined && userPrice !== null && userPrice !== ""), // Mark if manually set
//           lastPriceUpdate: new Date()
//         });
//       }

//       // Save product
//       await product.save();
//       console.log("Product saved successfully with updated price");

//       res.status(200).json({
//         success: true,
//         message: "Product updated successfully",
//         product,
//       });
//     } catch (error) {
//       console.error("Error updating product:", error);
//       return next(new Errorhandler("Error updating product", 500));
//     }
//   }
// );