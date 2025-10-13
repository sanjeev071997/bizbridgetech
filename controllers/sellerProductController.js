import mongoose from "mongoose";
import Product from "../models/sellerProductModel.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
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

// Function to add a new product
export const addProduct = catchAsyncErrors(async (req, res, next) => {
  const { name, image, mrp, category, stock, description, specifications } =
    req.body;

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

    // price calculation (no buyerCategory discount now)
    // let price = mrp;

    // Product create
    const newProduct = await Product.create({
      user: req.user._id,
      name,
      image: imageUrl,
      cloudinaryId,
      mrp,
      // price,   // final price = mrp
      category,
      stock,
      description,
      specifications,
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

// Update product discount & visible
export const updateProductCategoryAndVisibility = catchAsyncErrors(
  async (req, res, next) => {
    const { buyerCategory, visible, productId } = req.body;

    try {
      const product = await Product.findById(productId);
      if (!product) {
        return next(new Errorhandler("Product not found", 404));
      }

      // validate buyerCategory
      if (!mongoose.Types.ObjectId.isValid(buyerCategory)) {
        return next(new Errorhandler("Invalid buyerCategory ID", 400));
      }
      const buyerCatData = await BuyerCategory.findById(buyerCategory).select(
        "discount"
      );
      if (!buyerCatData) {
        return next(new Errorhandler("BuyerCategory not found", 404));
      }

      // discount calculate
      let price = product.mrp;
      if (buyerCatData.discount > 0) {
        price = product.mrp - (product.mrp * buyerCatData.discount) / 100;
      }

      // check if this buyerCategory already exists in productVisibility
      const existingVisibility = product.productVisibility.find(
        (v) => v.buyerCategory.toString() === buyerCategory.toString()
      );

      if (existingVisibility) {
        existingVisibility.visible = visible; // update
      } else {
        product.productVisibility.push({
          buyerCategory,
          visible: visible,
        });
      }

      product.price = price; // update latest price for this category
      await product.save();

      res.status(200).json({
        success: true,
        message: "Product updated successfully for buyerCategory visibility",
        product,
      });
    } catch (error) {
      console.log("Detailed Error:", error);
      return next(new Errorhandler("Error updating product", 500));
    }
  }
);

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
export const updateProduct = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const {
    image,
    name,
    category,
    mrp,
    stock,
    description,
    specifications,
    buyerCategory,
    price,
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
    product.image = imageUrl;
    product.cloudinaryId = cloudinaryId;
    product.mrp = mrp || product.mrp;
    product.category = category || product.category;
    product.stock = stock || product.stock;
    product.description = description || product.description;
    product.specifications = specifications || product.specifications;

    // ✅ Agar buyerCategory diya gaya hai to add/update
    if (buyerCategory) {
      const buyerCategoryDoc = await BuyerCategory.findById(buyerCategory);
      if (!buyerCategoryDoc) {
        return next(new Errorhandler("Buyer category not found", 404));
      }

      const discount = parseFloat(buyerCategoryDoc.discount) || 0;
      let finalPrice = mrp
        ? mrp - (mrp * discount) / 100
        : product.mrp - (product.mrp * discount) / 100;

      // agar price explicitly diya hai to override
      if (price) {
        finalPrice = price;
      }

      const alreadyExists = product.productVisibility.find(
        (v) =>
          v.buyerCategory._id.toString() === buyerCategoryDoc._id.toString()
      );

      if (!alreadyExists) {
        product.productVisibility.push({
          buyerCategory: buyerCategoryDoc._id,
          visible: true,
          price: finalPrice,
        });
      } else {
        alreadyExists.price = finalPrice;
        alreadyExists.visible = true;
      }
    }

    // ✅ Agar MRP change hua hai → sari buyerCategories ke price recalc karo
    if (mrp && mrp !== oldMrp) {
      for (let visibility of product.productVisibility) {
        if (
          visibility.buyerCategory &&
          visibility.buyerCategory.discount != null
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
    console.log("Detailed Error:", error);
    return next(new Errorhandler("Error updating product", 500));
  }
});

// Function to get a product by ID for Seller own products
export const getProductByUserId = catchAsyncErrors(async (req, res, next) => {
  const user = req.user.id;
  try {
    const product = await Product.find({ user: user })
      .populate("category", "name gst")
      .populate("user", "name phone businessName")
      .populate({
        path: "productVisibility.buyerCategory",
        select: "name discount",
      })
      .sort({ createdAt: -1 });
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

// Function to get a products for Buyer view with discount & visibility logic
// export const getBuyerProducts = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const buyerId = req.user._id;

//     console.log("Fetching products for buyer:", buyerId);

//     // Step 1: Buyer-Seller Connection
//     const connection = await BuyerSellerConnection.findOne({
//       buyer: buyerId,
//       status: "Accepted",
//     }).populate("buyerCategory", "name discount");

//     console.log("Buyer-Seller Connection:", connection);

//     if (!connection) {
//       return res.status(200).json({
//         success: true,
//         products: [],
//         message: "No accepted seller connection found for this buyer",
//       });
//     }

//     const buyerCategoryId = connection.buyerCategory._id.toString();
//     const discount = parseFloat(connection.buyerCategory.discount) || 0;
//     const sellerId = connection.seller;

//     // Step 2: Fetch seller's products (lightweight lean query)
//     const products = await Product.find({
//       user: sellerId,
//       $or: [
//         { productVisibility: { $exists: false } },
//         { productVisibility: { $size: 0 } },
//         {
//           productVisibility: {
//             $not: {
//               $elemMatch: {
//                 buyerCategory: buyerCategoryId,
//                 visible: false,
//               },
//             },
//           },
//         },
//       ],
//     })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .sort({ createdAt: -1 })
//       .lean(); // <---- no mongoose doc = faster + safer compare

//     const bulkOps = [];

//     for (const product of products) {
//       const visArray = product.productVisibility || [];

//       // convert buyerCategory to string for safe comparison
//       const hasExisting = visArray.some((v) => {
//         const catId =
//           typeof v.buyerCategory === "object"
//             ? v.buyerCategory._id?.toString()
//             : v.buyerCategory?.toString();
//         return catId === buyerCategoryId;
//       });

//       // skip if already exists
//       if (hasExisting) continue;

//       // calculate discount price only once
//       const priceAfterDiscount =
//         product.mrp - (product.mrp * discount) / 100;

//       bulkOps.push({
//         updateOne: {
//           filter: { _id: product._id },
//           update: {
//             $push: {
//               productVisibility: {
//                 buyerCategory: buyerCategoryId,
//                 visible: true,
//                 price: priceAfterDiscount,
//               },
//             },
//           },
//         },
//       });
//     }

//     // Step 3: bulk update only for missing ones
//     if (bulkOps.length > 0) {
//       await Product.bulkWrite(bulkOps);
//     }

//     // Step 4: Re-fetch products for correct visibility
//     const updatedProducts = await Product.find({ user: sellerId })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .populate("productVisibility.buyerCategory", "name discount")
//       .sort({ createdAt: -1 });

//     // Step 5: Prepare final data
//     const finalProducts = updatedProducts.map((product) => {
//       const matchedVis = product.productVisibility.find((v) => {
//         const catId =
//           typeof v.buyerCategory === "object"
//             ? v.buyerCategory._id?.toString()
//             : v.buyerCategory?.toString();
//         return catId === buyerCategoryId;
//       });

//       return {
//         ...product._doc,
//         appliedDiscount: discount,
//         finalPrice: matchedVis?.price || product.mrp,
//       };
//     });

//     res.status(200).json({
//       success: true,
//       products: finalProducts,
//     });
//   } catch (error) {
//     console.error(error);
//     return next(new Errorhandler("Error fetching buyer products", 500));
//   }
// });

// export const getBuyerProducts = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const buyerId = req.user._id;

//     console.log("Fetching products for buyer:", buyerId);

//     // Step 1: Buyer-Seller Connection
//     const connection = await BuyerSellerConnection.findOne({
//       buyer: buyerId,
//       status: "Accepted",
//     }).populate("buyerCategory", "name discount");

//     console.log("Buyer-Seller Connection:", connection);

//     if (!connection) {
//       return res.status(200).json({
//         success: true,
//         products: [],
//         message: "No accepted seller connection found for this buyer",
//       });
//     }

//     const buyerCategoryId = connection.buyerCategory._id.toString();
//     const discount = parseFloat(connection.buyerCategory.discount) || 0;
//     const sellerId = connection.seller;

//     // Step 2: Fetch seller's products
//     const products = await Product.find({
//       user: sellerId,
//     })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .populate("productVisibility.buyerCategory", "name discount")
//       .sort({ createdAt: -1 })
//       .lean();

//     const bulkOps = [];

//     for (const product of products) {
//       const visArray = product.productVisibility || [];

//       // convert buyerCategory to string for safe comparison
//       const hasExisting = visArray.some((v) => {
//         const catId =
//           typeof v.buyerCategory === "object"
//             ? v.buyerCategory._id?.toString()
//             : v.buyerCategory?.toString();
//         return catId === buyerCategoryId;
//       });

//       // calculate discount price only once
//       const priceAfterDiscount = product.mrp - (product.mrp * discount) / 100;

//       // If no visibility record exists for this buyerCategory, add it
//       if (!hasExisting) {
//         bulkOps.push({
//           updateOne: {
//             filter: { _id: product._id },
//             update: {
//               $push: {
//                 productVisibility: {
//                   buyerCategory: buyerCategoryId,
//                   visible: true,
//                   price: priceAfterDiscount,
//                 },
//               },
//             },
//           },
//         });
//       }
//     }

//     // Step 3: Bulk update missing visibility entries
//     if (bulkOps.length > 0) {
//       await Product.bulkWrite(bulkOps);
//     }

//     // Step 4: Re-fetch products for correct visibility
//     const updatedProducts = await Product.find({ user: sellerId })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .populate("productVisibility.buyerCategory", "name discount")
//       .sort({ createdAt: -1 });

//     // Step 5: Filter products for this buyer
//     const finalProducts = updatedProducts
//       .map((product) => {
//         const matchedVis = product.productVisibility.find((v) => {
//           const catId =
//             typeof v.buyerCategory === "object"
//               ? v.buyerCategory._id?.toString()
//               : v.buyerCategory?.toString();
//           return catId === buyerCategoryId;
//         });

//         // If visibility exists and is false, skip product
//         if (!matchedVis || matchedVis.visible === false) return null;

//         return {
//           ...product._doc,
//           appliedDiscount: discount,
//           finalPrice: matchedVis.price || product.mrp,
//         };
//       })
//       .filter(Boolean); // remove nulls

//     res.status(200).json({
//       success: true,
//       products: finalProducts,
//     });
//   } catch (error) {
//     console.error(error);
//     return next(new Errorhandler("Error fetching buyer products", 500));
//   }
// });

export const getBuyerProducts = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode; // "buyer" or "seller"

    
    console.log("Fetching products for user:", userId, "mode:", mode);

    let connections;

    if (mode === "buyer") {
      // Step 1: Find accepted connection for buyer
      connections = await BuyerSellerConnection.find({
        buyer: userId,
        status: "Accepted",
      }).populate("buyerCategory", "name discount");
    } else if (mode === "seller") {
      // Step 1: Find accepted connections for seller
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

    // Step 2: Collect relevant buyerCategory ids and seller ids
    const filterPairs = connections.map((conn) => ({
      buyerCategoryId: conn.buyerCategory._id.toString(),
      discount: parseFloat(conn.buyerCategory.discount) || 0,
      sellerId: conn.seller.toString(),
      buyerId: conn.buyer.toString(),
    }));

    // Step 3: Fetch products for all relevant sellers
    const products = await Product.find({
      user: { $in: filterPairs.map((p) => p.sellerId) },
      productVisibility: { $exists: true, $ne: [] },
    })
      .populate("category", "name gst")
      .populate("user", "name phone businessName")
      .populate("productVisibility.buyerCategory", "name discount")
      .sort({ createdAt: -1 })
      .lean();

    // Step 4: Filter products based on buyer/seller
    const finalProducts = [];

    for (const product of products) {
      for (const pair of filterPairs) {
        // const matchedVis = product.productVisibility.find((v) => {
        //   const catId =
        //     typeof v.buyerCategory === "object"
        //       ? v.buyerCategory._id?.toString()
        //       : v.buyerCategory?.toString();
        //   return catId === pair.buyerCategoryId && v.visible === true;
        // });
        const matchedVis = product.productVisibility.find((v) => {
          if (!v.buyerCategory) return false; // prevent null crash
          const catId =
            typeof v.buyerCategory === "object"
              ? v.buyerCategory._id?.toString()
              : v.buyerCategory?.toString();
          return catId === pair.buyerCategoryId && v.visible === true;
        });

        // Buyer mode: show only if connection buyer matches and seller matches product.user
        if (
          mode === "buyer" &&
          product.user._id.toString() === pair.sellerId &&
          matchedVis
        ) {
          finalProducts.push({
            ...product,
            appliedDiscount: pair.discount,
            finalPrice: matchedVis.price || product.mrp,
          });
          break; // no need to check other pairs
        }

        // Seller mode: show only products of this seller visible to connected buyers
        if (
          mode === "seller" &&
          product.user._id.toString() === userId.toString() &&
          matchedVis
        ) {
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

// Get Buyer Category Products
export const getProductsByBuyerCategoryId = catchAsyncErrors(
  async (req, res, next) => {
    const { buyerCategory } = req.params;
    const loginUserId = req.user?._id;

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

      // Fetch products (lean for faster read)
      const products = await Product.find({ user: loginUserId })
        .select("_id mrp name image productVisibility category")
        .lean(); // plain objects - faster

      if (!products.length) {
        return next(new Errorhandler("No products found", 404));
      }

      const bulkOps = [];

      // Prepare bulk operations: push only if buyerCategory not present (atomic)
      for (const p of products) {
        const vis = p.productVisibility || [];

        const exists = vis.some((v) => {
          // v.buyerCategory could be ObjectId or populated object — normalize to string
          const catId =
            v && v.buyerCategory
              ? v.buyerCategory._id
                ? v.buyerCategory._id.toString()
                : v.buyerCategory.toString()
              : null;
          return catId === buyerCategory;
        });

        if (!exists) {
          const priceAfterDiscount =
            discount > 0 ? p.mrp - (p.mrp * discount) / 100 : p.mrp;

          bulkOps.push({
            updateOne: {
              // atomic condition: only push when no existing buyerCategory
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
                  },
                },
              },
            },
          });
        }
      }

      // Execute bulk writes (only when needed)
      if (bulkOps.length > 0) {
        await Product.bulkWrite(bulkOps);
      }

      // Re-fetch products (populated) to return actual DB values
      const updatedProducts = await Product.find({ user: loginUserId })
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

        return {
          _id: product._id,
          name: product.name,
          mrp: product.mrp,
          image: product.image,
          category: product.category,
          buyerCategory: matched
            ? {
                id: matched.buyerCategory._id,
                name: matched.buyerCategory.name,
                discount: matched.buyerCategory.discount,
                price: matched.price,
              }
            : {
                id: buyerCategoryDoc._id,
                name: buyerCategoryDoc.name,
                discount: buyerCategoryDoc.discount,
                price: product.mrp,
              },
        };
      });

      return res
        .status(200)
        .json({ success: true, products: filteredProducts });
    } catch (error) {
      console.error("Detailed Error:", error);
      return next(
        new Errorhandler("Error fetching products by buyer category", 500)
      );
    }
  }
);

// Function to get products by category ID
// export const getProductsByCategoryId = catchAsyncErrors(
//   async (req, res, next) => {
//     const { category } = req.params;
//     try {
//       const products = await Product.find({ category })
//         .populate("category", "name gst")
//         .populate("user", "name phone")
//       .populate({
//         path: "productVisibility.buyerCategory",
//         select: "name discount",
//       })
//         .sort({ createdAt: -1 });
//       if (products.length === 0) {
//         return next(
//           new Errorhandler("No products found for this category", 404)
//         );
//       }
//       res.status(200).json({
//         success: true,
//         products,
//       });
//     } catch (error) {
//       console.log("Detailed Error:", error);
//       return next(new Errorhandler("Error fetching products by category", 500));
//     }
//   }
// );

// Function to get a product by ID
// export const getProductById = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;
//   try {
//     const product = await Product.findById(id).populate("category", "name gst").populate("user", "name phone")
//     .populate({
//         path: "productVisibility.buyerCategory",
//         select: "name discount",
//       })
//     if (!product) {
//       return next(new Errorhandler("Product not found", 404));
//     }
//     res.status(200).json({
//       success: true,
//       product,
//     });
//   } catch (error) {
//     console.log("Detailed Error:", error);
//     return next(new Errorhandler("Error fetching product", 500));
//   }
// });

// export const getBuyerProducts = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const buyerId = req.user._id;

//     console.log("Fetching products for buyer:", buyerId);

//     // Step 1: Buyer-Seller Connection
//     const connection = await BuyerSellerConnection.findOne({
//       buyer: buyerId,
//       status: "Accepted",
//     }).populate("buyerCategory", "name discount");

//     console.log("Buyer-Seller Connection:", connection);

//     if (!connection) {
//       return res.status(200).json({
//         success: true,
//         products: [],
//         message: "No accepted seller connection found for this buyer",
//       });
//     }

//     const buyerCategoryId = connection.buyerCategory._id.toString();
//     const discount = parseFloat(connection.buyerCategory.discount) || 0;
//     const sellerId = connection.seller;

//     // Step 2: Fetch seller's products
//     const products = await Product.find({
//       user: sellerId,
//     })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .populate("productVisibility.buyerCategory", "name discount")
//       .sort({ createdAt: -1 })
//       .lean();

//     const bulkOps = [];

//     for (const product of products) {
//       const visArray = product.productVisibility || [];

//       // convert buyerCategory to string for safe comparison
//       const hasExisting = visArray.some((v) => {
//         const catId =
//           typeof v.buyerCategory === "object"
//             ? v.buyerCategory._id?.toString()
//             : v.buyerCategory?.toString();
//         return catId === buyerCategoryId;
//       });

//       // calculate discount price only once
//       const priceAfterDiscount = product.mrp - (product.mrp * discount) / 100;

//       // If no visibility record exists for this buyerCategory, add it
//       if (!hasExisting) {
//         bulkOps.push({
//           updateOne: {
//             filter: { _id: product._id },
//             update: {
//               $push: {
//                 productVisibility: {
//                   buyerCategory: buyerCategoryId,
//                   visible: true,
//                   price: priceAfterDiscount,
//                 },
//               },
//             },
//           },
//         });
//       }
//     }

//     // Step 3: Bulk update missing visibility entries
//     if (bulkOps.length > 0) {
//       await Product.bulkWrite(bulkOps);
//     }

//     // Step 4: Re-fetch products for correct visibility
//     const updatedProducts = await Product.find({ user: sellerId })
//       .populate("category", "name gst")
//       .populate("user", "name phone businessName")
//       .populate("productVisibility.buyerCategory", "name discount")
//       .sort({ createdAt: -1 });

//     // Step 5: Filter products for this buyer
//     const finalProducts = updatedProducts
//       .map((product) => {
//         const matchedVis = product.productVisibility.find((v) => {
//           const catId =
//             typeof v.buyerCategory === "object"
//               ? v.buyerCategory._id?.toString()
//               : v.buyerCategory?.toString();
//           return catId === buyerCategoryId;
//         });

//         // If visibility exists and is false, skip product
//         if (!matchedVis || matchedVis.visible === false) return null;

//         return {
//           ...product._doc,
//           appliedDiscount: discount,
//           finalPrice: matchedVis.price || product.mrp,
//         };
//       })
//       .filter(Boolean); // remove nulls

//     res.status(200).json({
//       success: true,
//       products: finalProducts,
//     });
//   } catch (error) {
//     console.error(error);
//     return next(new Errorhandler("Error fetching buyer products", 500));
//   }
// });
