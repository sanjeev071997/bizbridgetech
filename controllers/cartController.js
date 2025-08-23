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

// Add to Cart
export const addCart = async (req, res) => {
  try {
    const { userId, productId, quantity } = req.body;

    const product = await SellerProduct.findById(productId);
    if (!product) return res.status(404).json({ message: "Product not found" });

    let cart = await Cart.findOne({ user: userId });
    if (!cart) {
      cart = new Cart({ user: userId, items: [] });
    }

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

    await cart.calculateTotals();
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

// Update Payment Option
export const paymentOptionUpdate = async (req, res) => {
  try {
    const { userId, paymentOptionId } = req.body;

    let cart = await Cart.findOne({ user: userId });
    if (!cart) return res.status(404).json({ message: "Cart not found" });

    cart.paymentOption = paymentOptionId;

    await cart.calculateTotals();
    await cart.save();

    res.json({ success: true, cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
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

export const getCart = async (req, res) => {
  try {
    const { userId } = req.params;

    const cart = await Cart.findOne({ user: userId })
      .populate({
        path: "items.product",
        select: "name image stock mrp price",
        populate: [
          { path: "category", select: "gst" },
          { path: "buyerCategory", select: "discount" },
          //   { path: "user", select: "name mode" },
        ],
      })
      .populate("paymentOption", "paymentType cashPayment");

    if (!cart) return res.json({ message: "Cart is empty" });

    res.json({ success: true, cart });
  } catch (error) {
    res.status(500).json({ message: error.message });
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
