import Cart from "../models/cartModel.js";
import SellerProduct from "../models/sellerProductModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Add item to cart
export const addCart = catchAsyncErrors(async (req, res, next) => {
    const { productId, quantity } = req.body;

    // Product validation
    const product = await SellerProduct.findById(productId);
    if (!product) {
        return next(new Errorhandler("Product not found", 404));
    }

    // Stock validation
    if (product.stock < quantity) {
        return next(new Errorhandler("Insufficient stock", 400));
    }

    // Find or create user cart
    let cart = await Cart.findOne({ user: req.user._id });

    if (!cart) {
        cart = new Cart({
            user: req.user._id,
            items: [],
            total: 0,
        });
    }

    // Check if product already exists in cart
    const existingItemIndex = cart.items.findIndex(
        item => item.product.toString() === productId
    );

    if (existingItemIndex > -1) {
        // Update quantity if product already exists
        cart.items[existingItemIndex].quantity += quantity;
    } else {
        // Add new item to cart
        cart.items.push({
            product: productId,
            quantity,
            price: product.price,
            name: product.name,
            image: product.image,
        });
    }

    await cart.save();
    await cart.populate("items.product", "name price image stock");

    res.status(200).json({
        success: true,
        cart,
    });
});

// Get user cart
export const getCart = catchAsyncErrors(async (req, res, next) => {
  const cart = await Cart.findOne({ user: req.user._id }).populate({
    path: "items.product",
    select: "name mrp price image stock category",
    populate: {
      path: "category",   // product -> category
      select: "name gst"  // category fields you want
    }
  });

  if (!cart) {
    return res.status(200).json({
      success: true,
      cart: { items: [], total: 0 },
    });
  }

  res.status(200).json({
    success: true,
    cart,
  });
});

// Remove item from cart
export const removeCartItem = catchAsyncErrors(async (req, res, next) => {
    const { itemId } = req.params;

    const cart = await Cart.findOne({ user: req.user._id });

    if (!cart) {
        return next(new Errorhandler("Cart not found", 404));
    }

    // Check if item exists in cart
    const itemIndex = cart.items.findIndex(
        item => item._id.toString() === itemId
    );

    if (itemIndex === -1) {
        return next(new Errorhandler("Item not found in cart", 404));
    }

    // Remove item from cart
    cart.items.splice(itemIndex, 1);

    await cart.save();
    await cart.populate("items.product", "name price image stock");

    res.status(200).json({
        success: true,
        cart,
    });
});

// Update item quantity in cart
export const updateCartItem = catchAsyncErrors(async (req, res, next) => {
    const { itemId } = req.params;
    const { quantity } = req.body;

    console.log(quantity, "quantity");

    if (quantity < 1) {
        return next(new Errorhandler("Quantity must be at least 1", 400));
    }

    const cart = await Cart.findOne({ user: req.user._id });

    if (!cart) {
        return next(new Errorhandler("Cart not found", 404));
    }

    // Find item in cart
    const itemIndex = cart.items.findIndex(
        item => item._id.toString() === itemId
    );

    if (itemIndex === -1) {
        return next(new Errorhandler("Item not found in cart", 404));
    }

    // Check product stock
    const product = await SellerProduct.findById(cart.items[itemIndex].product);
    if (product.stock < quantity) {
        return next(new Errorhandler("Insufficient stock", 400));
    }

    // Update quantity
    cart.items[itemIndex].quantity = quantity;

    await cart.save();
    await cart.populate("items.product", "name price image stock");

    res.status(200).json({
        success: true,
        cart,
    });
});

// Clear entire cart
export const clearCart = catchAsyncErrors(async (req, res, next) => {
    const cart = await Cart.findOne({ user: req.user._id });

    if (!cart) {
        return next(new Errorhandler("Cart not found", 404));
    }

    // Clear all items
    cart.items = [];
    cart.total = 0;

    await cart.save();

    res.status(200).json({
        success: true,
        message: "Cart cleared successfully",
        cart,
    });
});