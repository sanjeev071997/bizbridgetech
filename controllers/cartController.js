import mongoose from "mongoose";
import Cart from "../models/cartModel.js";
import SellerProduct from "../models/sellerProductModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import PaymentOption from "../models/paymentOption.js";

// Add to Cart
export const addCart = async (req, res) => {
  try {
    const { userId, productId, quantity = 1 } = req.body;

    // 🔹 Find product
    const product = await SellerProduct.findById(productId)
      .populate("user")
      .populate("category", "gst");

    if (!product)
      return res
        .status(404)
        .json({ success: false, message: "Product not found" });

    const sellerId = product.user?._id;
    if (!sellerId)
      return res
        .status(400)
        .json({ success: false, message: "Seller not found" });

    // 🔹 Verify buyer-seller connection
    const connection = await BuyerSellerConnection.findOne({
      buyer: userId,
      seller: sellerId,
      status: "Accepted",
    });

    if (!connection) {
      return res.status(403).json({
        success: false,
        message: "No buyer-seller connection found. Cannot add to cart.",
      });
    }

    const buyerCategory = connection.buyerCategory;

    // 🔹 Find product visibility for this buyer category
    const visibility = product.productVisibility.find(
      (v) => v.buyerCategory?.toString() === buyerCategory.toString()
    );

    if (!visibility) {
      return res.status(400).json({
        success: false,
        message: "This product is not visible for your buyer category.",
      });
    }

    // const basePrice = visibility.price || product.mrp;
    const basePrice = visibility.price;
    const gstPercent = product.category?.gst || 0;
    const gstAmount = (basePrice * gstPercent) / 100;
    const finalPrice = basePrice + gstAmount;

    // 🔹 Get payment option (for discount)
    const paymentOption = await PaymentOption.findOne({
      buyerCategory,
      user: sellerId,
    });

    let discountPercent = 0;
    if (paymentOption?.cashPayment?.discountPercent) {
      discountPercent = paymentOption.cashPayment.discountPercent;
    }

    const discountFromPayment = (finalPrice * quantity * discountPercent) / 100;

    // 🔹 Find or create cart
    let cart = await Cart.findOne({ user: userId, seller: sellerId });
    if (!cart) {
      cart = new Cart({
        user: userId,
        seller: sellerId,
        items: [],
        paymentOption: paymentOption?._id || null,
        subTotal: 0,
        discountFromPayment: discountFromPayment || 0,
        total: 0,
      });
    } else if (paymentOption?._id) {
      cart.paymentOption = paymentOption._id;
    }

    // 🔹 Add or update item
    const existingItem = cart.items.find(
      (i) => i.product.toString() === productId
    );

    if (existingItem) {
      existingItem.quantity += quantity;
      existingItem.mrp = basePrice;
      existingItem.gstAmount = gstAmount;
      existingItem.finalPrice = finalPrice;
    } else {
      cart.items.push({
        product: productId,
        quantity,
        mrp: product.mrp,
        discountPrice: basePrice,
        gstAmount,
        finalPrice,
      });
    }

    // 🔹 Calculate cart totals
    const subTotal = cart.items.reduce(
      (sum, i) => sum + i.finalPrice * i.quantity,
      0
    );

    const totalDiscountFromPayment = (subTotal * discountPercent) / 100;

    const total = subTotal - totalDiscountFromPayment;

    cart.subTotal = subTotal;
    cart.discountFromPayment = totalDiscountFromPayment;
    cart.total = total;

    await cart.save();

    res.status(200).json({
      success: true,
      message: "Cart updated successfully",
      cart,
    });
  } catch (error) {
    console.error("❌ addCart error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

// Update Cart (quantity)
export const updateCart = async (req, res) => {
  try {
    const { userId, productId, quantity } = req.body;

    if (!userId || !productId || quantity === undefined) {
      return res
        .status(400)
        .json({ message: "userId, productId and quantity are required" });
    }

    // User ki saari carts dhundho
    const carts = await Cart.find({ user: userId });

    if (!carts || carts.length === 0) {
      return res.status(404).json({ message: "Cart not found" });
    }

    let targetCart = null;
    let targetItem = null;

    // Har cart mein product ko dhundho
    for (const cart of carts) {
      const item = cart.items.find(
        (i) => i.product.toString() === productId.toString()
      );
      if (item) {
        targetCart = cart;
        targetItem = item;
        break;
      }
    }

    if (!targetCart || !targetItem) {
      return res.status(404).json({ message: "Item not in any cart" });
    }
    // Update quantity
    if (quantity <= 0) {
      targetCart.items = targetCart.items.filter(
        (i) => i.product.toString() !== productId.toString()
      );
    } else {
      targetItem.quantity = quantity;
    }

    await targetCart.calculateTotals();
    await targetCart.save();

    res.status(200).json({
      success: true,
      message: "Cart updated successfully",
      cart: targetCart,
    });
  } catch (error) {
    console.error("Error in updateCart:", error);
    res.status(500).json({ message: error.message });
  }
};

// Update Payment Option
export const paymentOptionUpdate = async (req, res) => {
  try {
    const { userId, paymentOptionId } = req.body;

    if (!userId || !paymentOptionId) {
      return res
        .status(400)
        .json({
          success: false,
          message: "userId and paymentOptionId are required",
        });
    }

    let cart = await Cart.findOne({ user: userId }).populate("items.product");
    if (!cart) {
      return res
        .status(404)
        .json({ success: false, message: "Cart not found" });
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

// Gat Cart
export const getCart = async (req, res, next) => {
  try {
    const { userId, seller, buyerCategories = [] } = req.body;

    const sellerIds = Array.isArray(seller) ? seller : [seller];
    const buyerCategoryIds = Array.isArray(buyerCategories)
      ? buyerCategories
      : [buyerCategories];

    // Fetch carts
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

    // Combine all items with their parent cart’s totals
    const allItems = [];
    for (const cart of carts) {
      const items = cart.items || [];
      for (const item of items) {
        allItems.push({
          ...(item?.toObject ? item.toObject() : item),
          subTotal: cart.subTotal || 0,
          discountFromPayment: cart.discountFromPayment || 0,
          total: cart.total || 0,
        });
      }
    }

    if (allItems.length === 0) {
      return res.json({
        success: true,
        message: "Cart has no items",
        cart: [],
      });
    }

    // Extract seller IDs safely
    const sellerIdsFromItems = [
      ...new Set(
        allItems
          .map((item) => item?.product?.user?._id?.toString())
          .filter(Boolean)
      ),
    ];

    // Get buyer-seller accepted connections
    const connections = await BuyerSellerConnection.find({
      buyer: userId,
      seller: { $in: sellerIdsFromItems },
      status: "Accepted",
    });

    const updatedItems = allItems
      .map((item) => {
        const product = item?.product;
        if (!product) return null;

        const sellerId = product?.user?._id?.toString();
        const connection = connections.find(
          (conn) => conn.seller.toString() === sellerId
        );
        if (!connection) return null;

        const buyerCategory = connection.buyerCategory?.toString();

        const matchedVisibilityList = product?.productVisibility?.filter(
          (pv) =>
            pv?.visible === true &&
            buyerCategoryIds.includes(pv?.buyerCategory?._id?.toString())
        );

        if (!matchedVisibilityList || matchedVisibilityList.length === 0) {
          return null;
        }

        const matchedVisibility = matchedVisibilityList[0];
        const finalPrice =
          matchedVisibility?.price || product.price || item.mrp || 0;

        return {
          ...item,
          product: {
            ...(product?.toObject ? product.toObject() : product),
            productVisibility: matchedVisibilityList,
            price: finalPrice,
            buyerCategory,
            visible: matchedVisibility?.visible ?? true,
          },
        };
      })
      .filter(Boolean);

    return res.status(200).json({
      success: true,
      message: "Cart fetched successfully",
      totalItems: updatedItems.length,
      cart: updatedItems,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Error fetching cart",
      error: error.message,
    });
  }
};

// Remove item from Cart
export const removeItemFromCart = async (req, res) => {
  try {
    const { userId, productId, itemId } = req.body;

    if (!userId || (!itemId && !productId)) {
      return res.status(400).json({
        success: false,
        message: "userId and either itemId or productId are required",
      });
    }

    // Build match condition to find the correct cart
    const matchCondition = {
      user: userId,
      items: {
        $elemMatch: itemId ? { _id: itemId } : { product: productId },
      },
    };

    // Find the exact cart that contains the item
    const cart = await Cart.findOne(matchCondition);
    if (!cart) {
      return res.status(404).json({
        success: false,
        message: "Cart or item not found",
      });
    }

    // Remove item manually
    cart.items = cart.items.filter((item) =>
      itemId
        ? item._id.toString() !== itemId
        : item.product.toString() !== productId
    );

    // If cart empty, reset totals
    if (cart.items.length === 0) {
      cart.subTotal = 0;
      cart.total = 0;
      cart.discountFromPayment = 0;
      await cart.save();
      return res.json({
        success: true,
        message: "Cart is now empty",
        cart,
      });
    }

    // Recalculate totals
    if (typeof cart.calculateTotals === "function") {
      await cart.calculateTotals();
    } else {
      const subTotal = cart.items.reduce(
        (acc, item) => acc + (item.finalPrice || 0),
        0
      );
      cart.subTotal = subTotal;
      cart.total = subTotal - (cart.discountFromPayment || 0);
    }

    await cart.save();

    res.json({
      success: true,
      message: "Item removed successfully",
      cart,
    });
  } catch (error) {
    console.error("❌ Remove item error:", error);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: error.message,
    });
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
