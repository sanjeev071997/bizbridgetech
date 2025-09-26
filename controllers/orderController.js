import mongoose from "mongoose";
import Order from "../models/orderModel.js";
import Cart from "../models/cartModel.js";
import Product from "../models/sellerProductModel.js"; // SellerProduct
import ErrorHandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Create Order
export const createOrder = async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.id })
      .populate("items.product")
      .populate("user");

    if (!cart) {
      return res
        .status(404)
        .json({ success: false, message: "Cart not found" });
    }

    // Default process flow
    const defaultSteps = [
      { step: "Enquiry Received", completed: true, completedAt: new Date() },
      { step: "Proforma Invoice" },
      { step: "Proforma Accepted" },
      { step: "Payment Received" },
      { step: "Invoice Uploaded" },
      { step: "Dispatch" },
      { step: "Delivered" },
    ];

    // Create order
    const newOrder = await Order.create({
      buyer: cart.user._id,
      items: cart.items.map((i) => ({
        product: i.product._id,
        name: i.product.name,
        image: i.product.image,
        price: i.product.price,
        mrp: i.mrp,
        quantity: i.quantity,
        discountPrice: i.discountPrice,
        gstAmount: i.gstAmount,
        finalPrice: i.finalPrice,
        // Save sellerId from product
        seller: i.product.user,
      })),
      subTotal: cart.subTotal,
      discountFromPayment: cart.discountFromPayment,
      total: cart.total,
      paymentOption: cart.paymentOption?._id,
      processFlow: defaultSteps,
    });

    const order = await Order.findById(newOrder._id)
      .populate("buyer", "name mode")
      .populate({
        path: "items.seller",
        select: "name mode",
      });
    // (Optional) Empty cart after order
    await Cart.findByIdAndDelete(cart._id);

    res.status(201).json({ success: true, message: "Order created", order });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
};

// Get Buyer Orders
export const getBuyerOrders = catchAsyncErrors(async (req, res, next) => {
  const orders = await Order.find({ buyer: req.user._id })
    .populate({
      path: "items.seller",
      select: "name phone mode", 
    })
    .populate("paymentOption", "paymentType")
    .populate("buyer", "name phone mode")
    .sort({ date: -1 });

  res.status(200).json({
    success: true,
    orders,
  });
});

// 🟢 Get Seller Orders
export const getSellerOrders = catchAsyncErrors(async (req, res, next) => {
  const orders = await Order.find()
    .populate("buyer", "name phone mode")
    .populate("paymentOption", "paymentType")
    .populate("items.seller", "name phone mode") // seller info
    .sort({ createdAt: -1 });

  // filter items current seller 
  const sellerOrders = orders
    .map((order) => {
      const sellerItems = order.items.filter(
        (item) =>
          item.seller && item.seller._id.toString() === req.user._id.toString()
      );

      if (sellerItems.length > 0) {
        return {
          ...order._doc,
          items: sellerItems.map((item) => ({
            _id: item._id,
            name: item.name,
            image: item.image,
            price: item.price,
            mrp: item.mrp,
            quantity: item.quantity,
            discountPrice: item.discountPrice,
            gstAmount: item.gstAmount,
            finalPrice: item.finalPrice,
            seller: item.seller, // populated seller info
          })),
        };
      }
      return null;
    })
    .filter((o) => o !== null);

  res.status(200).json({
    success: true,
    orders: sellerOrders,
  });
});


// 🟢 Update Order Status 
export const updateOrderStatus = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { seller, orderStatus } = req.body;

  const order = await Order.findById(id);
  if (!order) {
    return next(new ErrorHandler("Order not found", 404));
  }

  // Check if seller matches any item in this order
  const sellerOwnsItem = order.items.some(
    (item) => item.seller.toString() === seller
  );

  if (!sellerOwnsItem) {
    return next(
      new ErrorHandler(
        "You cannot update order status for items that are not yours",
        403
      )
    );
  }

  // Update only if seller owns at least one item
  order.orderStatus = orderStatus;
  await order.save();

  res.status(200).json({
    success: true,
    message: "Order status updated successfully",
    order,
  });
});

// 🟢 Update Order Process Step (Seller Restricted)
export const updateProcessStep = catchAsyncErrors(async (req, res, next) => {
  const { orderId } = req.params;
  const { step, itemId } = req.body; 
  const sellerId = req.user._id; // logged in seller

  if (!mongoose.Types.ObjectId.isValid(orderId))
    return next(new ErrorHandler("Invalid Order ID", 400));

  const order = await Order.findById(orderId).populate("items.product");
  if (!order) return next(new ErrorHandler("Order not found", 404));

  // Find the item in order belonging to this seller
  const item = order.items.find(
    (i) =>
      i.seller.toString() === sellerId.toString()
  );

  if (!item) return next(new ErrorHandler("You cannot update this item", 403));

  // Find the step in processFlow
  const stepIndex = order.processFlow.findIndex((s) => s.step === step);
  if (stepIndex === -1) return next(new ErrorHandler("Step not found", 404));

  // Mark step as completed
  order.processFlow[stepIndex].completed = true;
  order.processFlow[stepIndex].completedAt = new Date();

  await order.save();

  res.status(200).json({
    success: true,
    message: `Step '${step}' updated successfully for your item`,
    processFlow: order.processFlow,
  });
});


// Delete Order (Admin or Buyer can cancel)
export const deleteOrder = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  const order = await Order.findById(id);
  if (!order) {
    return next(new ErrorHandler("Order not found", 404));
  }

  await order.deleteOne();

  res.status(200).json({
    success: true,
    message: "Order deleted successfully",
  });
});
