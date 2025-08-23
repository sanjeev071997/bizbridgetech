import Order from "../models/orderModel.js";
import Cart from "../models/cartModel.js";
import Product from "../models/sellerProductModel.js"; // SellerProduct
import ErrorHandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";


// 🟢 Create Order
export const createOrder = catchAsyncErrors(async (req, res, next) => {
  const { productId, quantity, paymentOption } = req.body;

  // Product check
  const product = await Product.findById(productId).populate("buyerCategory", "discount");
  if (!product) {
    return next(new ErrorHandler("Product not found", 404));
  }

  // Stock check
  if (product.stock < quantity) {
    return next(new ErrorHandler("Insufficient stock available", 400));
  }

  // Discount handling
  let discount = 0;
  if (product.buyerCategory?.discount) {
    discount = Number(product.buyerCategory.discount);
  }

  let price = product.mrp;
  if (discount > 0) {
    price = price - (price * discount / 100);
  }

  const totalAmount = price * quantity;

  // Create order
  const order = await Order.create({
    productId,
    quantity,
    amount: totalAmount,
    paymentOption,
    buyer: req.user._id,  // logged-in user
  });

  // Reduce stock
  product.stock -= quantity;
  await product.save();

  res.status(201).json({
    success: true,
    message: "Order placed successfully",
    order,
  });
});
// 🟢 Create Order
// export const createOrder = catchAsyncErrors(async (req, res, next) => {
//   const { productId, quantity, paymentOption } = req.body;

//   // Product check
//   const product = await Product.findById(productId).populate("buyerCategory", "discount");
//   if (!product) {
//     return next(new ErrorHandler("Product not found", 404));
//   }

//   // Stock check
//   if (product.stock < quantity) {
//     return next(new ErrorHandler("Insufficient stock available", 400));
//   }

//   // Discount handling
//   let discount = 0;
//   if (product.buyerCategory?.discount) {
//     discount = Number(product.buyerCategory.discount);
//   }

//   let price = product.mrp;
//   if (discount > 0) {
//     price = price - (price * discount / 100);
//   }

//   const totalAmount = price * quantity;

//   // Create order
//   const order = await Order.create({
//     productId,
//     quantity,
//     amount: totalAmount,
//     paymentOption,
//     buyer: req.user._id,  // logged-in user
//   });

//   // Reduce stock
//   product.stock -= quantity;
//   await product.save();

//   // 🟢 Remove product from cart
//   await Cart.findOneAndUpdate(
//     { user: req.user._id },
//     { $pull: { items: { product: productId } } },  // product remove from cart
//     { new: true }
//   );

//   res.status(201).json({
//     success: true,
//     message: "Order placed successfully",
//     order,
//   });
// });


// // 🟢 Get Buyer Orders
// export const getMyOrders = catchAsyncErrors(async (req, res, next) => {
//   const orders = await Order.find({ buyer: req.user._id })
//     .populate("productId", "name image mrp price user")
//     .populate("paymentOption", "paymentType")
//     .populate("buyer", "name phone mode")

//     .sort({ date: -1 });

//   res.status(200).json({
//     success: true,
//     orders,
//   });
// });

// 🟢 Get Buyer Orders
export const getMyOrders = catchAsyncErrors(async (req, res, next) => {
  const orders = await Order.find({ buyer: req.user._id })
    .populate({
      path: "productId",
      select: "name image user",   // product fields
      populate: {
        path: "user",                        // product ka user
        select: "name phone mode",          // jo fields chahiye
      },
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
    .populate({
      path: "productId",
      match: { user: req.user._id }, // seller ke products
      select: "name price user",
    //   populate: { path: "user", select: "name phone mode" },
    })
    .populate("buyer", "name phone mode")
    .populate("paymentOption", "paymentType")
    .sort({ date: -1 });

  // filter null (jo products seller ke nahi hai unke orders skip)
  const sellerOrders = orders.filter(order => order.productId);

  res.status(200).json({
    success: true,
    orders: sellerOrders,
  });
});


// 🟢 Update Order Status
export const updateOrderStatus = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { status } = req.body;

  const order = await Order.findById(id);
  if (!order) {
    return next(new ErrorHandler("Order not found", 404));
  }

  order.status = status;
  await order.save();

  res.status(200).json({
    success: true,
    message: "Order status updated successfully",
    order,
  });
});


// 🟢 Delete Order (Admin or Buyer can cancel)
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
