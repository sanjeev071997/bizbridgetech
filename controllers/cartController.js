// import Cart from "../models/cartModel.js";
// import SellerProduct from "../models/sellerProductModel.js";
// import Errorhandler from "../utils/Errorhandler.js";
// import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// // Add item to cart
// export const addCart = catchAsyncErrors(async (req, res, next) => {
//     const { productId, quantity } = req.body;

//     // Product validation
//     const product = await SellerProduct.findById(productId);
//     if (!product) {
//         return next(new Errorhandler("Product not found", 404));
//     }

//     // Stock validation
//     if (product.stock < quantity) {
//         return next(new Errorhandler("Insufficient stock", 400));
//     }

//     // Find or create user cart
//     let cart = await Cart.findOne({ user: req.user._id });

//     if (!cart) {
//         cart = new Cart({
//             user: req.user._id,
//             items: [],
//             total: 0,
//         });
//     }

//     // Check if product already exists in cart
//     const existingItemIndex = cart.items.findIndex(
//         item => item.product.toString() === productId
//     );

//     if (existingItemIndex > -1) {
//         // Update quantity if product already exists
//         cart.items[existingItemIndex].quantity += quantity;
//     } else {
//         // Add new item to cart
//         cart.items.push({
//             product: productId,
//             quantity,
//             price: product.price,
//             name: product.name,
//             image: product.image,
//         });
//     }

//     await cart.save();
//     await cart.populate("items.product", "name price image stock");

//     res.status(200).json({
//         success: true,
//         cart,
//     });
// });

// // Get user cart
// export const getCart = catchAsyncErrors(async (req, res, next) => {
//   const cart = await Cart.findOne({ user: req.user._id }).populate({
//     path: "items.product",
//     select: "mrp stock category buyerCategory user",
//     populate: [
//       {
//         path: "category",   // product ka category
//         select: "name gst",
//       },
//       {
//         path: "user",       // product ka user (seller)
//         select: "name mode",
//       },
//     //   {
//     //     path: "buyerCategory",       // product ka buyerCategory
//     //     select: "name discount",
//     //   },
//     ],
//   }).populate("user", "name mode"); // Populate user details (buyer)

//   if (!cart) {
//     return res.status(200).json({
//       success: true,
//       cart: { items: [], total: 0 },
//     });
//   }

//   res.status(200).json({
//     success: true,
//     cart,
//   });
// });

// // Remove item from cart
// export const removeCartItem = catchAsyncErrors(async (req, res, next) => {
//     const { itemId } = req.params;

//     const cart = await Cart.findOne({ user: req.user._id });

//     if (!cart) {
//         return next(new Errorhandler("Cart not found", 404));
//     }

//     // Check if item exists in cart
//     const itemIndex = cart.items.findIndex(
//         item => item._id.toString() === itemId
//     );

//     if (itemIndex === -1) {
//         return next(new Errorhandler("Item not found in cart", 404));
//     }

//     // Remove item from cart
//     cart.items.splice(itemIndex, 1);

//     await cart.save();
//     await cart.populate("items.product", "name price image stock");

//     res.status(200).json({
//         success: true,
//         cart,
//     });
// });

// // Update item quantity in cart
// export const updateCartItem = catchAsyncErrors(async (req, res, next) => {
//     const { itemId } = req.params;
//     const { quantity } = req.body;

//     if (quantity < 1) {
//         return next(new Errorhandler("Quantity must be at least 1", 400));
//     }

//     const cart = await Cart.findOne({ user: req.user._id });

//     if (!cart) {
//         return next(new Errorhandler("Cart not found", 404));
//     }

//     // Find item in cart
//     const itemIndex = cart.items.findIndex(
//         item => item._id.toString() === itemId
//     );

//     if (itemIndex === -1) {
//         return next(new Errorhandler("Item not found in cart", 404));
//     }

//     // Check product stock
//     const product = await SellerProduct.findById(cart.items[itemIndex].product);
//     if (product.stock < quantity) {
//         return next(new Errorhandler("Insufficient stock", 400));
//     }

//     // Update quantity
//     cart.items[itemIndex].quantity = quantity;

//     await cart.save();
//     await cart.populate("items.product", "name price image stock");

//     res.status(200).json({
//         success: true,
//         cart,
//     });
// });

// // Clear entire cart
// export const clearCart = catchAsyncErrors(async (req, res, next) => {
//     const cart = await Cart.findOne({ user: req.user._id });

//     if (!cart) {
//         return next(new Errorhandler("Cart not found", 404));
//     }

//     // Clear all items
//     cart.items = [];
//     cart.total = 0;

//     await cart.save();

//     res.status(200).json({
//         success: true,
//         message: "Cart cleared successfully",
//         cart,
//     });
// });

import Cart from "../models/cartModel.js";
import SellerProduct from "../models/sellerProductModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";

// Add to Cart
// export const addCart = async (req, res) => {
//   try {
//     const { userId, productId, quantity, paymentOption } = req.body;

//     const product = await SellerProduct.findById(productId);
//     if (!product) return res.status(404).json({ message: "Product not found" });

//     let cart = await Cart.findOne({ user: userId });
//     if (!cart) {
//       cart = new Cart({ user: userId, items: [] });
//     }

//     const existingItem = cart.items.find(
//       (i) => i.product.toString() === productId
//     );

//     if (existingItem) {
//       existingItem.quantity += quantity;
//     } else {
//       cart.items.push({
//         product: productId,
//         quantity,
//         mrp: product.mrp,
//         paymentOption
//       });
//     }

//     await cart.calculateTotals();
//     await cart.save();

//     res.json({ success: true, cart });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// export const addCart = async (req, res) => {
//   try {
//     const { userId, productId, quantity, paymentOption } = req.body;

//     const product = await SellerProduct.findById(productId);
//     if (!product) return res.status(404).json({ message: "Product not found" });

//     let cart = await Cart.findOne({ user: userId });
//     if (!cart) {
//       cart = new Cart({ user: userId, items: [], paymentOption });
//     } else {
//       // update payment option each time if provided
//       if (paymentOption) cart.paymentOption = paymentOption;
//     }

//     const existingItem = cart.items.find(
//       (i) => i.product.toString() === productId
//     );

//     if (existingItem) {
//       existingItem.quantity += quantity;
//     } else {
//       cart.items.push({
//         product: productId,
//         quantity,
//         mrp: product.mrp,
//       });
//     }

//     await cart.calculateTotals();
//     await cart.save();

//     res.json({ success: true, cart });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

export const addCart = async (req, res) => {
  try {
    const { userId, productId, quantity, paymentOption } = req.body;

    // find product
    const product = await SellerProduct.findById(productId).populate("user");
    if (!product) return res.status(404).json({ message: "Product not found" });

    const sellerId = product.user?._id;
    if (!sellerId) return res.status(400).json({ message: "Seller not found" });

    // find existing cart for this buyer-seller pair
    let cart = await Cart.findOne({ user: userId, seller: sellerId });
    if (!cart) {
      cart = new Cart({
        user: userId,
        seller: sellerId,
        items: [],
        paymentOption,
      });
    } else if (paymentOption) {
      cart.paymentOption = paymentOption;
    }

    // check if item exists
    const existingItem = cart.items.find(
      (i) => i.product.toString() === productId
    );

    if (existingItem) {
      existingItem.quantity += quantity;
    } else {
      cart.items.push({
        product: productId,
        quantity,
        mrp: product.mrp,
      });
    }

    // calculate totals (optional)
    cart.totalAmount = cart.items.reduce(
      (sum, i) => sum + i.mrp * i.quantity,
      0
    );

    await cart.save();
    res.json({ success: true, cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};


// Update Cart (quantity)
export const updateCart = async (req, res) => {
  try {
    const { userId, productId, quantity } = req.body;

    let cart = await Cart.findOne({ user: userId });
    if (!cart) return res.status(404).json({ message: "Cart not found" });

    const item = cart.items.find((i) => i.product.toString() === productId);
    if (!item) return res.status(404).json({ message: "Item not in cart" });

    if (quantity <= 0) {
      cart.items = cart.items.filter((i) => i.product.toString() !== productId);
    } else {
      item.quantity = quantity;
    }

    await cart.calculateTotals();
    await cart.save();

    res.json({ success: true, cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// // Update Payment Option
// export const paymentOptionUpdate = async (req, res) => {
//   try {
//     const { userId, paymentOptionId } = req.body;

//     let cart = await Cart.findOne({ user: userId });
//     if (!cart) return res.status(404).json({ message: "Cart not found" });

//     cart.paymentOption = paymentOptionId;

//     await cart.calculateTotals();
//     await cart.save();

//     res.json({ success: true, cart });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// Update Payment Option
export const paymentOptionUpdate = async (req, res) => {
  try {
    const { userId, paymentOptionId } = req.body;

    if (!userId || !paymentOptionId) {
      return res
        .status(400)
        .json({ success: false, message: "userId and paymentOptionId are required" });
    }

    let cart = await Cart.findOne({ user: userId }).populate("items.product");
    if (!cart) {
      return res.status(404).json({ success: false, message: "Cart not found" });
    }

    // update payment option
    cart.paymentOption = paymentOptionId;

    // recalculate totals
    if (cart.calculateTotals) {
      await cart.calculateTotals();
    }

    await cart.save();

    res.status(200).json({
      success: true,
      message: "Payment option updated successfully",
      cart,
    });
  } catch (error) {
    console.error("Error in paymentOptionUpdate:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};


// Get Cart
// export const getCart = async (req, res) => {
//   try {
//     const { userId } = req.params;

//     const cart = await Cart.findOne({ user: userId })
//       .populate("items.product")
//       .populate("paymentOption");
//     if (!cart) return res.json({ message: "Cart is empty" });

//     res.json({ success: true, cart });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };


// New Code for Get Cart
// export const getCart = async (req, res, next) => {
//   try {
//     const { userId, seller, buyerCategories } = req.body;

//     // ✅ Ensure seller is array
//     const sellerIds = Array.isArray(seller) ? seller : [seller];

//     // ✅ Fetch all carts for given sellers
//     const carts = await Cart.find({
//       user: userId,
//       seller: { $in: sellerIds },
//     })
//       .populate({
//         path: "items.product",
//         model: "SellerProduct",
//         select: "name image stock mrp price productVisibility user category",
//         populate: [
//           { path: "category", select: "gst" },
//           { path: "user", select: "name businessName businessAddress" },
//           { path: "productVisibility.buyerCategory", select: "discount" },
//         ],
//       })
//       .populate("paymentOption", "paymentType cashPayment");

//     // 🧠 No carts found
//     if (!carts || carts.length === 0) {
//       return res.json({ success: true, message: "Cart is empty", cart: [] });
//     }

//     // ✅ Combine all items from multiple carts
//     const allItems = carts.flatMap((cart) => cart.items || []);

//     if (allItems.length === 0) {
//       return res.json({
//         success: true,
//         message: "Cart has no items",
//         cart: [],
//       });
//     }

//     // ✅ Extract seller IDs from products
//     const sellerIdsFromItems = [
//       ...new Set(
//         allItems
//           .map((item) => item?.product?.user?._id?.toString())
//           .filter(Boolean)
//       ),
//     ];

//     // ✅ Find buyer-seller connections
//     const connections = await BuyerSellerConnection.find({
//       buyer: userId,
//       seller: { $in: sellerIdsFromItems },
//       status: "Accepted",
//     });

//     if (connections.length === 0) {
//       return res.status(200).json({
//         success: true,
//         message: "No accepted buyer-seller connections found",
//         cart: allItems,
//       });
//     }

//     // ✅ Map products with correct buyer category and visibility
//     const updatedItems = allItems
//       .map((item) => {
//         const product = item.product;
//         if (!product) return null;

//         const sellerId = product.user?._id?.toString();
//         const connection = connections.find(
//           (conn) => conn.seller.toString() === sellerId
//         );

//         if (!connection) return null;

//         const buyerCategory = connection.buyerCategory;
//         const matchedVisibility = product.productVisibility?.find(
//           (pv) =>
//             pv.buyerCategory?.toString() === buyerCategory?.toString() &&
//             pv.visible === true
//         );

//         const finalPrice =
//           matchedVisibility?.price || product.price || item.mrp || 0;

//         return {
//           ...item.toObject(),
//           product: {
//             ...product.toObject(),
//             price: finalPrice,
//             buyerCategory,
//             visible: matchedVisibility?.visible ?? true,
//           },
//         };
//       })
//       .filter(Boolean);

//     // ✅ Return unified cart data
//     return res.status(200).json({
//       success: true,
//       message: "Cart fetched successfully",
//       totalItems: updatedItems.length,
//       cart: updatedItems,
//     });
//   } catch (error) {
//     console.error("Error fetching cart:", error);
//     return next(new Errorhandler("Error fetching cart", 500));
//   }
// };

export const getCart = async (req, res, next) => {
  try {
    const { userId, seller, buyerCategories = [] } = req.body;

    // ✅ Normalize arrays
    const sellerIds = Array.isArray(seller) ? seller : [seller];
    const buyerCategoryIds = Array.isArray(buyerCategories)
      ? buyerCategories
      : [buyerCategories];

    // ✅ Fetch carts
    const carts = await Cart.find({
      user: userId,
      seller: { $in: sellerIds },
    })
      .populate({
        path: "items.product",
        model: "SellerProduct",
        select: "name image stock mrp price productVisibility user category",
        populate: [
          { path: "category", select: "gst" },
          { path: "user", select: "name businessName businessAddress" },
          { path: "productVisibility.buyerCategory", select: "discount" },
        ],
      })
      .populate("paymentOption", "paymentType cashPayment");

    if (!carts || carts.length === 0) {
      return res.json({ success: true, message: "Cart is empty", cart: [] });
    }

    // ✅ Combine all items from multiple carts
    const allItems = carts.flatMap((cart) => cart.items || []);

    if (allItems.length === 0) {
      return res.json({
        success: true,
        message: "Cart has no items",
        cart: [],
      });
    }

    // ✅ Extract seller IDs from products
    const sellerIdsFromItems = [
      ...new Set(
        allItems
          .map((item) => item?.product?.user?._id?.toString())
          .filter(Boolean)
      ),
    ];

    // ✅ Find buyer-seller connections
    const connections = await BuyerSellerConnection.find({
      buyer: userId,
      seller: { $in: sellerIdsFromItems },
      status: "Accepted",
    });

    // ✅ Filter + map items
    const updatedItems = allItems
      .map((item) => {
        const product = item.product;
        if (!product) return null;

        const sellerId = product.user?._id?.toString();
        const connection = connections.find(
          (conn) => conn.seller.toString() === sellerId
        );
        if (!connection) return null;

        const buyerCategory = connection.buyerCategory?.toString();

        // ✅ Only keep productVisibility entries matching buyerCategories
        const matchedVisibilityList = product.productVisibility?.filter(
          (pv) =>
            pv.visible === true &&
            buyerCategoryIds.includes(pv?.buyerCategory?._id?.toString())
        );

        if (!matchedVisibilityList || matchedVisibilityList.length === 0) {
          return null; // skip if no matching visibility found
        }

        const matchedVisibility = matchedVisibilityList[0]; // pick first match
        const finalPrice =
          matchedVisibility?.price || product.price || item.mrp || 0;

        return {
          ...item.toObject(),
          product: {
            ...product.toObject(),
            // 🧠 Keep only the matched productVisibility entry
            productVisibility: matchedVisibilityList,
            price: finalPrice,
            buyerCategory,
            visible: matchedVisibility?.visible ?? true,
          },
        };
      })
      .filter(Boolean);

    // ✅ Return filtered data
    return res.status(200).json({
      success: true,
      message: "Cart fetched successfully",
      totalItems: updatedItems.length,
      cart: updatedItems,
    });
  } catch (error) {
    console.error("Error fetching cart:", error);
    return next(new Errorhandler("Error fetching cart", 500));
  }
};


// // Remove item
// export const removeItemFromCart = async (req, res) => {
//   try {
//     const { userId, productId } = req.body;

//     let cart = await Cart.findOne({ user: userId });
//     if (!cart) return res.status(404).json({ message: "Cart not found" });

//     cart.items = cart.items.filter((i) => i.product.toString() !== productId);

//     await cart.calculateTotals();
//     await cart.save();

//     res.json({ success: true, cart });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// Remove item
export const removeItemFromCart = async (req, res) => {
  try {
    const { userId, productId } = req.body;

    if (!userId || !productId) {
      return res
        .status(400)
        .json({ message: "userId and productId are required" });
    }

    const cart = await Cart.findOneAndUpdate(
      { user: userId },
      { $pull: { items: { product: productId } } },
      { new: true }
    );

    if (!cart) return res.status(404).json({ message: "Cart not found" });

    await cart.calculateTotals();
    await cart.save();

    // res.json({ success: true, cart });
    if (cart.items.length === 0) {
      return res.json({ success: true, message: "Cart is now empty" });
    }
    res.json({ success: true, message: "Item removed successfully", cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Clear Cart
export const clearCart = async (req, res) => {
  try {
    const { userId } = req.body;

    let cart = await Cart.findOne({ user: userId });
    if (!cart) return res.status(404).json({ message: "Cart not found" });

    cart.items = [];
    cart.subTotal = 0;
    cart.gstTotal = 0;
    cart.grandTotal = 0;
    cart.discountAmount = 0;
    cart.finalPayable = 0;

    await cart.save();

    res.json({ success: true, message: "Cart cleared" }); 
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
