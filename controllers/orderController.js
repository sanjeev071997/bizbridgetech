// import mongoose from "mongoose";
// import Order from "../models/orderModel.js";
// import Cart from "../models/cartModel.js";
// import Invoice from "../models/invoiceModel.js";
// import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
// import ErrorHandler from "../utils/Errorhandler.js";
// import { generateQRCode } from "../utils/generateQRCode.js";

// // Create Order
// export const createOrder = async (req, res) => {
//   try {
//     const { seller, selectPaymentType } = req.body;

//     console.log("selectPaymentType",  selectPaymentType, seller);

//     if (!seller) {
//       return res.status(400).json({
//         success: false,
//         message: "Seller ID is required",
//       });
//     }

//     const cart = await Cart.findOne({ user: req.user.id, seller })
//       .populate("items.product")
//       .populate("user")
//       .populate("paymentOption");

//     if (!cart || !cart.items.length) {
//       return res.status(404).json({
//         success: false,
//         message: "Cart not found or empty",
//       });
//     }

//     const defaultSteps = [
//       { step: "Enquiry Received" },
//       { step: "Proforma Invoice" },
//       { step: "Proforma Accepted" },
//       { step: "Payment QR Generated" },
//       { step: "Payment Received" },
//       { step: "Invoice Uploaded" },
//       { step: "Dispatch" },
//       { step: "Delivered" },
//     ];
//     let orderSubTotal = 0;
//     const orderItems = cart.items.map((i) => {
//       const base = Number(i.discountPrice || 0);
//       const gstPercent = Number(i?.category?.gst || 0);

//       const gstAmount = (base * gstPercent) / 100;
//       const finalPrice = base + gstAmount;

//       const subTotal = finalPrice * i.quantity;
//       orderSubTotal += subTotal;

//       return {
//         product: i.product._id,
//         name: i.product.name,
//         image: i.product.image,
//         price: i.product.price || i.mrp || 0,
//         mrp: i.mrp,
//         quantity: i.quantity,
//         discountPrice: i.discountPrice,
//         gstAmount: gstAmount,
//         finalPrice: finalPrice,
//         subTotal: subTotal,
//         discountFromPayment: 0,
//         seller: i.product.user,

//         category: i.category
//           ? {
//               _id: i.category._id,
//               name: i.category.name,
//               gst: i.category.gst,
//             }
//           : null,
//       };
//     });

//     // Order level totals
//     const discount = Number(cart.discountFromPayment || 0);
//     const orderTotal = orderSubTotal - discount;
//     const newOrder = await Order.create({
//       buyer: cart.user._id,
//       items: orderItems,
//       subTotal: orderSubTotal,
//       discountFromPayment: discount,
//       total: orderTotal,
//       paymentOption: cart.paymentOption?._id,
//       processFlow: defaultSteps,
//       selectPaymentType
//     });

//     // Fetch clean populated order
//     const order = await Order.findById(newOrder._id)
//       .populate("buyer", "name mode")
//       .populate({
//         path: "items.seller",
//         select: "name mode",
//       });

//     // Remove cart
//     await Cart.findByIdAndDelete(cart._id);

//     res.status(201).json({
//       success: true,
//       message: "Order created successfully",
//       order,
//     });
//   } catch (error) {
//     // console.error("createOrder error:", error);
//     // res.status(500).json({
//     //   success: false,
//     //   message: "Server Error",
//     // });
//      return next(new ErrorHandler(error.message, 500))
//   }
// };

// // Get Buyer Orders
// export const getBuyerOrders = catchAsyncErrors(async (req, res, next) => {
//   const orders = await Order.find({ buyer: req.user._id })
//     .populate({
//       path: "items.seller",
//       select: "name phone mode",
//     })
//     .populate("paymentOption", "paymentType")
//     .populate("buyer", "name phone mode")
//     // .sort({ date: -1 });
//     .sort({ createdAt: -1 });

//   res.status(200).json({
//     success: true,
//     orders,
//   });
// });

// // Get Seller Orders
// export const getSellerOrders = catchAsyncErrors(async (req, res, next) => {
//   const orders = await Order.find()
//     .populate("buyer", "name phone mode")
//     .populate("paymentOption", "paymentType")
//     .populate("items.seller", "name phone mode") // seller info
//     .sort({ createdAt: -1 });

//   // filter items current seller
//   const sellerOrders = orders
//     .map((order) => {
//       const sellerItems = order.items.filter(
//         (item) =>
//           item.seller && item.seller._id.toString() === req.user._id.toString()
//       );

//       if (sellerItems.length > 0) {
//         return {
//           ...order._doc,
//           items: sellerItems.map((item) => ({
//             _id: item._id,
//             name: item.name,
//             image: item.image,
//             price: item.price,
//             mrp: item.mrp,
//             quantity: item.quantity,
//             discountPrice: item.discountPrice,
//             gstAmount: item.gstAmount,
//             finalPrice: item.finalPrice,
//             seller: item.seller, // populated seller info
//             category: item.category,
//           })),
//         };
//       }
//       return null;
//     })
//     .filter((o) => o !== null);

//   res.status(200).json({
//     success: true,
//     orders: sellerOrders,
//   });
// });

// // Update Order Status
// export const updateOrderStatus = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;
//   const { seller, orderStatus } = req.body;

//   const order = await Order.findById(id);
//   if (!order) {
//     return next(new ErrorHandler("Order not found", 404));
//   }

//   // Check if seller matches any item in this order
//   const sellerOwnsItem = order.items.some(
//     (item) => item.seller.toString() === seller
//   );

//   if (!sellerOwnsItem) {
//     return next(
//       new ErrorHandler(
//         "You cannot update order status for items that are not yours",
//         403
//       )
//     );
//   }

//   // Update only if seller owns at least one item
//   order.orderStatus = orderStatus;
//   await order.save();

//   res.status(200).json({
//     success: true,
//     message: "Order status updated successfully",
//     order,
//   });
// });

// // Update Order Process Step (Seller Restricted)
// export const updateProcessStep = catchAsyncErrors(async (req, res, next) => {
//   const { orderId } = req.params;
//   const { step, itemId } = req.body;
//   const sellerId = req.user._id;

//   if (!mongoose.Types.ObjectId.isValid(orderId))
//     return next(new ErrorHandler("Invalid Order ID", 400));

//   const order = await Order.findById(orderId).populate("items.product");
//   if (!order) return next(new ErrorHandler("Order not found", 404));

//   // Find the item in order belonging to this seller
//   const item = order.items.find(
//     (i) => i.seller.toString() === sellerId.toString()
//   );

//   if (!item) return next(new ErrorHandler("You cannot update this item", 403));

//   // Find the step in processFlow
//   const stepIndex = order.processFlow.findIndex((s) => s.step === step);
//   if (stepIndex === -1) return next(new ErrorHandler("Step not found", 404));

//   // Mark step as completed
//   order.processFlow[stepIndex].completed = true;
//   order.processFlow[stepIndex].completedAt = new Date();

//   await order.save();

//   res.status(200).json({
//     success: true,
//     message: `Step '${step}' updated successfully for your item`,
//     processFlow: order.processFlow,
//   });
// });

// // Delete Order (Admin or Buyer can cancel)
// export const deleteOrder = catchAsyncErrors(async (req, res, next) => {
//   const { id } = req.params;

//   const order = await Order.findById(id);
//   if (!order) {
//     return next(new ErrorHandler("Order not found", 404));
//   }

//   await order.deleteOne();

//   res.status(200).json({
//     success: true,
//     message: "Order deleted successfully",
//   });
// });

// const getFinalPaymentType = (paymentOption, order) => {
//   if (!paymentOption) return null;

//   const type = paymentOption.paymentType;
//   if (type === "Both") {
//     const selected = order?.selectPaymentType?.toLowerCase();

//     if (selected === "cash") return "Cash";
//     if (selected === "credit") return "Credit";
//     throw new Error(
//       "Order has payment type 'Both' but no valid selectPaymentType found (must be 'cash' or 'credit')"
//     );
//   }
//   if (type === "Cash" || type === "Credit") return type;
//   throw new Error("Invalid paymentType in paymentOption");
// };

// export const updateOrderProcessStep = async (req, res, next) => {
//   try {
//     const { orderId, step, actionBy } = req.body;

//     if (!mongoose.Types.ObjectId.isValid(orderId))
//       return next(new ErrorHandler("Invalid Order ID", 400));

//     const order = await Order.findById(orderId)
//       .populate("paymentOption")
//       .populate({
//         path: "items.seller",
//         select: "name email bankDetails accountName upiId",
//         populate: {
//           path: "bankDetails",
//           select:
//             "bankName accountName upiId accountNumber ifscCode branchName branchAddress",
//         },
//       })
//       .populate("buyer");

//     if (!order)
//       return res
//         .status(404)
//         .json({ success: false, message: "Order not found" });

//     const finalPaymentType = getFinalPaymentType(order.paymentOption, order);

//     if (!finalPaymentType)
//       return next(new ErrorHandler("Unable to determine payment type", 400));

//     // Helper function for marking step complete
//     const markStepComplete = (stepName, extraData = {}) => {
//       let stepObj = order.processFlow.find((s) => s.step === stepName);
//       if (!stepObj) {
//         order.processFlow.push({
//           step: stepName,
//           completed: true,
//           completedAt: new Date(),
//           ...extraData,
//         });
//       } else {
//         stepObj.completed = true;
//         stepObj.completedAt = new Date();
//         Object.assign(stepObj, extraData);
//       }
//     };

//     const createStepIfNotExists = (stepName, extraData = {}) => {
//       let stepObj = order.processFlow.find((s) => s.step === stepName);
//       if (!stepObj) {
//         order.processFlow.push({
//           step: stepName,
//           completed: false,
//           ...extraData,
//         });
//       } else {
//         Object.keys(extraData).forEach((key) => {
//           stepObj[key] = extraData[key];
//         });
//       }
//     };

//     // INVOICE CREATION WITH FINAL PAYMENT TYPE
//     const createInvoiceOnEnquiry = async () => {
//       const existing = await Invoice.findOne({ order: order._id });
//       if (existing) return;

//       if (!order.paymentOption)
//         throw new Error("Payment Option not found for this order");

//       let invoiceData = {
//         order: order._id,
//         buyer: order.buyer._id,
//         seller: order.items[0]?.seller?._id,
//         amount: order.total,
//         status: "Pending",
//         bankStatement: [],
//         paymentType: finalPaymentType,
//       };

//       // CASH → INVOICE PAID
//       if (finalPaymentType === "Cash") {
//         invoiceData.status = "Paid";
//         invoiceData.paidAt = new Date();

//         invoiceData.bankStatement.push({
//           date: new Date(),
//           description: "Cash Payment Received",
//           debit: 0,
//           credit: order.total,
//           balance: 0,
//         });
//       }

//       // CREDIT → CREDIT TERMS
//       if (finalPaymentType === "Credit") {
//         const pay = order.paymentOption;

//         invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
//         invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
//         invoiceData.interestStartAfterDays =
//           pay.creditPayment.interestStartAfterDays;

//         const dueDate = new Date();
//         dueDate.setDate(
//           dueDate.getDate() + pay.creditPayment.creditPeriodDays
//         );
//         invoiceData.dueDate = dueDate;

//         const interestStart = new Date(dueDate);
//         interestStart.setDate(
//           interestStart.getDate() + pay.creditPayment.interestStartAfterDays
//         );
//         invoiceData.interestAccrualStartDate = interestStart;
//       }

//       await Invoice.create(invoiceData);
//     };

//     // QR FOR FINAL PAYMENT TYPE
//     const generateQRCodeForPayment = async () => {
//       const sellerBank = order.items[0]?.seller?.bankDetails;

//       if (!sellerBank?.upiId)
//         throw new Error("Seller UPI ID not found.");

//       if (finalPaymentType === "Cash") {
//         return await generateQRCode(sellerBank.upiId, order.total);
//       }

//       return null; // no QR for Credit
//     };

//     // MAIN LOGIC
//     switch (step) {
//       case "Enquiry Received":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can send Enquiry Received",
//           });

//         markStepComplete("Enquiry Received", {
//           visibleTo: ["buyer", "seller"],
//         });

//         await createInvoiceOnEnquiry();
//         break;

//       case "Proforma Invoice":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can send Proforma Invoice",
//           });

//         markStepComplete("Proforma Invoice", {
//           visibleTo: ["buyer", "seller"],
//         });
//         break;

//       case "Proforma Accepted":
//         if (actionBy !== "buyer")
//           return res.status(403).json({
//             success: false,
//             message: "Only buyer can accept Proforma",
//           });

//         order.orderStatus = "Processing";

//         markStepComplete("Proforma Accepted", {
//           visibleTo: ["buyer", "seller"],
//         });

//         // Payment type wise logic
//         if (finalPaymentType === "Cash") {
//           const qrCode = await generateQRCodeForPayment();

//           markStepComplete("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             qrCodeUrl: qrCode,
//             paymentType: "Cash",
//           });

//           order.qrCodeData = qrCode;
//         }

//         if (finalPaymentType === "Credit") {
//           const pay = order.paymentOption;

//           const dueDate = new Date();
//           dueDate.setDate(
//             dueDate.getDate() +
//               (pay.creditPayment?.creditPeriodDays || 0)
//           );

//           const creditDetails = {
//             paymentType: "Credit",
//             totalAmount: order.total,
//             creditPeriodDays: pay.creditPayment.creditPeriodDays,
//             interestRatePerYear: pay.creditPayment.interestRatePerYear,
//             interestStartAfterDays:
//               pay.creditPayment.interestStartAfterDays,
//             dueDate,
//             interestStartDate: new Date(
//               dueDate.getTime() +
//                 (pay.creditPayment.interestStartAfterDays || 0) *
//                   86400000
//             ),
//           };

//           createStepIfNotExists("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             creditDetails,
//             qrCodeUrl: null,
//             paymentType: "Credit",
//           });

//           order.creditPaymentDetails = creditDetails;
//         }
//         break;

//       case "Payment QR Generated":
//         if (finalPaymentType === "Credit") {
//           if (actionBy !== "buyer")
//             return res.status(403).json({
//               success: false,
//               message:
//                 "For credit payments, only buyer can complete this step",
//             });

//           const existingStep = order.processFlow.find(
//             (s) => s.step === "Payment QR Generated"
//           );

//           markStepComplete("Payment QR Generated", {
//             ...existingStep,
//             visibleTo: ["buyer", "seller"],
//             paymentType: "Credit",
//             qrCodeUrl: null,
//           });
//         }

//         if (finalPaymentType === "Cash") {
//           if (actionBy !== "seller")
//             return res.status(403).json({
//               success: false,
//               message:
//                 "For cash payments, only seller can complete this step",
//             });

//           const qr = await generateQRCodeForPayment();

//           markStepComplete("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             qrCodeUrl: qr,
//             paymentType: "Cash",
//           });

//           order.qrCodeData = qr;
//         }
//         break;

//       case "Payment Received":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can confirm payment",
//           });

//         markStepComplete("Payment Received", {
//           visibleTo: ["buyer", "seller"],
//           paymentType: finalPaymentType,
//         });
//         break;

//       case "Invoice Uploaded":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can upload invoice",
//           });

//         const itemSummary = order.items.map((i) => i.productName).join(", ");
//         const totalItems = order.items.length;
//         const totalAmount = order.total;

//         markStepComplete("Invoice Uploaded", {
//           visibleTo: ["buyer", "seller"],
//           invoiceSummary: { itemSummary, totalItems, totalAmount },
//         });
//         break;

//       case "Dispatch":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can dispatch order",
//           });

//         markStepComplete("Dispatch", { visibleTo: ["buyer", "seller"] });
//         break;

//       case "Delivered":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can mark as delivered",
//           });

//         order.orderStatus = "Completed";

//         markStepComplete("Delivered", {
//           visibleTo: ["buyer", "seller"],
//         });
//         break;

//       default:
//         return res
//           .status(400)
//           .json({ success: false, message: "Invalid step" });
//     }

//     await order.save();

//     res.status(200).json({
//       success: true,
//       message: `${step} marked as completed.`,
//       paymentTypeUsed: finalPaymentType,
//       data: order,
//     });
//   } catch (err) {
//     return next(new ErrorHandler(err.message, 500))
//   }
// };

// export const updateOrderItem = async (req, res, next) => {
//   try {
//     const { orderId, items } = req.body;

//     if (!orderId || !items?.length) {
//       return res.status(400).json({
//         success: false,
//         message: "orderId and items array are required",
//       });
//     }

//     const order = await Order.findById(orderId);
//     if (!order)
//       return res.status(404).json({
//         success: false,
//         message: "Order not found",
//       });

//     let newSubTotal = 0;
//     order.items.forEach((item) => {
//       const reqItem = items.find((i) => i.itemId === item._id.toString());
//       if (!reqItem) return;

//       const qty = reqItem.quantity;
//       item.quantity = qty;

//       const perUnitFinal =
//         (item.discountPrice || 0) + (item.gstAmount || 0);

//       const updatedFinal = perUnitFinal * qty;
//       item.finalPrice = Number(updatedFinal.toFixed(2));

//       newSubTotal += item.finalPrice;
//     });
//     const oldSubTotal = order.subTotal || 1;
//     const oldDiscount = order.discountFromPayment || 0;

//     const discountRatio = oldDiscount / oldSubTotal;
//     const newDiscount = newSubTotal * discountRatio;
//     order.subTotal = Number(newSubTotal.toFixed(2));
//     order.discountFromPayment = Number(newDiscount.toFixed(2));
//     order.total = Number((order.subTotal - order.discountFromPayment).toFixed(2));

//     await order.save();

//     return res.status(200).json({
//       success: true,
//       message: "Order items updated successfully",
//       order,
//     });
//   } catch (error) {
//     return next(new ErrorHandler(error.message, 500))
//   }
// };

import mongoose from "mongoose";
import Order from "../models/orderModel.js";
import Cart from "../models/cartModel.js";
import Invoice from "../models/invoiceModel.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import ErrorHandler from "../utils/Errorhandler.js";
import { generateQRCode } from "../utils/generateQRCode.js";

// Create Order
export const createOrder = async (req, res, next) => {
  try {
    const { seller, selectPaymentType } = req.body;

    console.log("selectPaymentType", selectPaymentType, seller);

    if (!seller) {
      return res.status(400).json({
        success: false,
        message: "Seller ID is required",
      });
    }

    const cart = await Cart.findOne({ user: req.user.id, seller })
      .populate("items.product")
      .populate("user")
      .populate("paymentOption");

    if (!cart || !cart.items.length) {
      return res.status(404).json({
        success: false,
        message: "Cart not found or empty",
      });
    }

    // ❗ REMOVE invalid/deleted products
    const validItems = cart.items.filter((i) => i.product);

    if (!validItems.length) {
      return res.status(400).json({
        success: false,
        message: "Products in cart are no longer available",
      });
    }

    const defaultSteps = [
      { step: "Enquiry Received" },
      { step: "Proforma Invoice" },
      { step: "Proforma Accepted" },
      { step: "Payment QR Generated" },
      { step: "Payment Received" },
      { step: "Invoice Uploaded" },
      { step: "Dispatch" },
      { step: "Delivered" },
    ];

    let orderSubTotal = 0;

    const orderItems = validItems.map((i) => {
      const base = Number(i.discountPrice || 0);
      const gstPercent = Number(i?.category?.gst || 0);

      const gstAmount = (base * gstPercent) / 100;
      const finalPrice = base + gstAmount;

      const subTotal = finalPrice * i.quantity;
      orderSubTotal += subTotal;

      return {
        product: i.product._id,
        name: i.product.name,
        image: i.product.image,
        price: i.product.price || i.mrp || 0,
        mrp: i.mrp,
        quantity: i.quantity,
        discountPrice: i.discountPrice,
        gstAmount,
        finalPrice,
        subTotal,
        discountFromPayment: 0,
        seller: i.product.user,

        category: i.category
          ? {
              _id: i.category._id,
              name: i.category.name,
              gst: i.category.gst,
            }
          : null,
      };
    });

    const discount = Number(cart.discountFromPayment || 0);
    const orderTotal = orderSubTotal - discount;

    const newOrder = await Order.create({
      buyer: cart.user?._id,
      items: orderItems,
      subTotal: orderSubTotal,
      discountFromPayment: discount,
      total: orderTotal,
      paymentOption: cart.paymentOption?._id,
      processFlow: defaultSteps,
      selectPaymentType,
    });

    const order = await Order.findById(newOrder._id)
      .populate("buyer", "name mode")
      .populate({
        path: "items.seller",
        select: "name mode",
      });

    await Cart.findByIdAndDelete(cart._id);

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      order,
    });
  } catch (error) {
    console.error(error.stack);
    return next(new ErrorHandler(error.message, 500));
  }
};
// // Get Buyer Orders
// export const getBuyerOrders = catchAsyncErrors(async (req, res) => {
//   const orders = await Order.find({ buyer: req.user._id })
//     .populate({
//       path: "items.seller",
//       select: "name phone mode",
//     })
//     .populate("paymentOption", "paymentType")
//     .populate("buyer", "name phone mode")
//     .sort({ createdAt: -1 });

//   res.status(200).json({
//     success: true,
//     orders,
//   });
// });

// Get Buyer Orders with Pagination
export const getBuyerOrders = catchAsyncErrors(async (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  const orders = await Order.find({ buyer: req.user._id })
    .populate({
      path: "items.seller",
      select: "name phone mode",
    })
    .populate("paymentOption", "paymentType")
    .populate("buyer", "name phone mode")
    .sort({ createdAt: -1 });

  // 👉 pagination
  const paginatedOrders = orders.slice(startIndex, endIndex);

  res.status(200).json({
    success: true,
    page,
    limit,
    totalOrders: orders.length,
    totalPages: Math.ceil(orders.length / limit),
    orders: paginatedOrders,
  });
});

// // Get Seller Orders
// export const getSellerOrders = catchAsyncErrors(async (req, res, next) => {
//   const orders = await Order.find()
//     .populate("buyer", "name phone mode")
//     .populate("paymentOption", "paymentType")
//     .populate("items.seller", "name phone mode")
//     .sort({ createdAt: -1 });

//   const sellerOrders = orders
//     .map((order) => {
//       const sellerItems = order.items.filter(
//         (item) =>
//           item.seller && item.seller._id.toString() === req.user._id.toString()
//       );

//       if (sellerItems.length > 0) {
//         return {
//           ...order._doc,
//           items: sellerItems.map((item) => ({
//             _id: item._id,
//             name: item.name,
//             image: item.image,
//             price: item.price,
//             mrp: item.mrp,
//             quantity: item.quantity,
//             discountPrice: item.discountPrice,
//             gstAmount: item.gstAmount,
//             finalPrice: item.finalPrice,
//             seller: item.seller,
//             category: item.category,
//           })),
//         };
//       }
//       return null;
//     })
//     .filter((o) => o !== null);

//   res.status(200).json({
//     success: true,
//     orders: sellerOrders,
//   });
// });

export const getSellerOrders = catchAsyncErrors(async (req, res, next) => {
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  const orders = await Order.find()
    .populate("buyer", "name phone mode")
    .populate("paymentOption", "paymentType")
    .populate("items.seller", "name phone mode")
    .sort({ createdAt: -1 });

  const sellerOrders = orders
    .map((order) => {
      const sellerItems = order.items.filter(
        (item) =>
          item.seller &&
          item.seller._id.toString() === req.user._id.toString()
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
            seller: item.seller,
            category: item.category,
          })),
        };
      }
      return null;
    })
    .filter(Boolean);

  // 👉 pagination AFTER seller filtering
  const paginatedOrders = sellerOrders.slice(startIndex, endIndex);

  res.status(200).json({
    success: true,
    page,
    limit,
    totalOrders: sellerOrders.length,
    totalPages: Math.ceil(sellerOrders.length / limit),
    orders: paginatedOrders,
  });
});

// Update Order Status
export const updateOrderStatus = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { seller, orderStatus } = req.body;

  const order = await Order.findById(id);
  if (!order) {
    return next(new ErrorHandler("Order not found", 404));
  }

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

  order.orderStatus = orderStatus;
  await order.save();

  res.status(200).json({
    success: true,
    message: "Order status updated successfully",
    order,
  });
});

// Update Order Process Step (Seller Restricted)
export const updateProcessStep = catchAsyncErrors(async (req, res, next) => {
  const { orderId } = req.params;
  const { step, itemId } = req.body;
  const sellerId = req.user._id;

  if (!mongoose.Types.ObjectId.isValid(orderId))
    return next(new ErrorHandler("Invalid Order ID", 400));

  const order = await Order.findById(orderId).populate("items.product");
  if (!order) return next(new ErrorHandler("Order not found", 404));

  const item = order.items.find(
    (i) => i.seller.toString() === sellerId.toString()
  );

  if (!item) return next(new ErrorHandler("You cannot update this item", 403));

  const stepIndex = order.processFlow.findIndex((s) => s.step === step);
  if (stepIndex === -1) return next(new ErrorHandler("Step not found", 404));

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

const getFinalPaymentType = (paymentOption, order) => {
  if (!paymentOption) return null;

  const type = paymentOption.paymentType;
  if (type === "Both") {
    const selected = order?.selectPaymentType?.toLowerCase();

    if (selected === "cash") return "Cash";
    if (selected === "credit") return "Credit";
    throw new Error(
      "Order has payment type 'Both' but no valid selectPaymentType found (must be 'cash' or 'credit')"
    );
  }
  if (type === "Cash" || type === "Credit") return type;
  throw new Error("Invalid paymentType in paymentOption");
};

// Helper function to get next month-end date
const getNextMonthEndDate = (date) => {
  if (!date) return null;

  const d = new Date(date);
  const year = d.getFullYear();
  const month = d.getMonth();

  // Get last day of current month
  const lastDay = new Date(year, month + 1, 0);

  // If date is already past current month-end, get next month's end
  if (d > lastDay) {
    return new Date(year, month + 2, 0);
  }

  return lastDay;
};

// Helper function to check if date is last day of month
const isLastDayOfMonth = (date) => {
  const d = new Date(date);
  const nextDay = new Date(d);
  nextDay.setDate(d.getDate() + 1);
  return d.getMonth() !== nextDay.getMonth();
};

// Update Order Process Step
// export const updateOrderProcessStep = async (req, res, next) => {
//   try {
//     const { orderId, step, actionBy } = req.body;

//     if (!mongoose.Types.ObjectId.isValid(orderId))
//       return next(new ErrorHandler("Invalid Order ID", 400));

//     const order = await Order.findById(orderId)
//       .populate("paymentOption")
//       .populate({
//         path: "items.seller",
//         select: "name email bankDetails accountName upiId",
//         populate: {
//           path: "bankDetails",
//           select:
//             "bankName accountName upiId accountNumber ifscCode branchName branchAddress",
//         },
//       })
//       .populate("buyer");

//     if (!order)
//       return res
//         .status(404)
//         .json({ success: false, message: "Order not found" });

//     const finalPaymentType = getFinalPaymentType(order.paymentOption, order);

//     if (!finalPaymentType)
//       return next(new ErrorHandler("Unable to determine payment type", 400));

//     const markStepComplete = (stepName, extraData = {}) => {
//       let stepObj = order.processFlow.find((s) => s.step === stepName);
//       if (!stepObj) {
//         order.processFlow.push({
//           step: stepName,
//           completed: true,
//           completedAt: new Date(),
//           ...extraData,
//         });
//       } else {
//         stepObj.completed = true;
//         stepObj.completedAt = new Date();
//         Object.assign(stepObj, extraData);
//       }
//     };

//     const createStepIfNotExists = (stepName, extraData = {}) => {
//       let stepObj = order.processFlow.find((s) => s.step === stepName);
//       if (!stepObj) {
//         order.processFlow.push({
//           step: stepName,
//           completed: false,
//           ...extraData,
//         });
//       } else {
//         Object.keys(extraData).forEach((key) => {
//           stepObj[key] = extraData[key];
//         });
//       }
//     };

//     // UPDATED INVOICE CREATION LOGIC FOR CREDIT
//     const createInvoiceOnEnquiry = async () => {
//       const existing = await Invoice.findOne({ order: order._id });
//       if (existing) return;

//       if (!order.paymentOption)
//         throw new Error("Payment Option not found for this order");

//       let invoiceData = {
//         order: order._id,
//         buyer: order.buyer._id,
//         seller: order.items[0]?.seller?._id,
//         amount: order.total,
//         status: "Pending",
//         bankStatement: [],
//         paymentType: finalPaymentType,
//       };

//       // CASH → INVOICE PAID
//       if (finalPaymentType === "Cash") {
//         invoiceData.status = "Paid";
//         invoiceData.paidAt = new Date();

//         invoiceData.bankStatement.push({
//           date: new Date(),
//           description: "Cash Payment Received",
//           debit: 0,
//           credit: order.total,
//           balance: 0,
//         });
//       }

//       // CREDIT → CREDIT TERMS WITH CORRECT LOGIC
//       if (finalPaymentType === "Credit") {
//         const pay = order.paymentOption;

//         invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
//         invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
//         invoiceData.interestStartAfterDays =
//           pay.creditPayment.interestStartAfterDays;

//         // Calculate dueDate (invoice date + creditPeriodDays)
//         const invoiceDate = new Date();
//         const dueDate = new Date(invoiceDate);
//         dueDate.setDate(dueDate.getDate() + pay.creditPayment.creditPeriodDays);
//         invoiceData.dueDate = dueDate;

//         // CORRECTION: interestAccrualStartDate = dueDate (not dueDate + interestStartAfterDays)
//         // Because interest starts immediately after due date
//         invoiceData.interestAccrualStartDate = dueDate;

//         // Store interestStartAfterDays for reference (30 days)
//         // This is the grace period before interest actually accrues
//         invoiceData.gracePeriodDays = pay.creditPayment.interestStartAfterDays;

//         // First interest application will be on next month-end after dueDate
//         const firstInterestDate = getNextMonthEndDate(dueDate);
//         invoiceData.nextInterestApplicationDate = firstInterestDate;

//         // Initial bank statement entry
//         invoiceData.bankStatement.push({
//           date: new Date(),
//           description: "Invoice Created (Credit)",
//           debit: order.total,
//           credit: 0,
//           balance: order.total,
//           paymentStatus: "Approved",
//         });
//       }

//       await Invoice.create(invoiceData);
//     };

//     const generateQRCodeForPayment = async () => {
//       const sellerBank = order.items[0]?.seller?.bankDetails;

//       if (!sellerBank?.upiId) throw new Error("Seller UPI ID not found.");

//       if (finalPaymentType === "Cash") {
//         return await generateQRCode(sellerBank.upiId, order.total);
//       }

//       return null;
//     };

//     switch (step) {
//       case "Enquiry Received":
//         if (actionBy !== "seller")
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can send Enquiry Received",
//           });

//         // Seller Enquiry Received complete करते ही
//         markStepComplete("Enquiry Received", {
//           visibleTo: ["buyer", "seller"],
//         });

//         // Order status set to "Pending"
//         order.orderStatus = "Pending";

//         // Proforma Invoice auto true - both sides
//         markStepComplete("Proforma Invoice", {
//           visibleTo: ["buyer", "seller"],
//           autoCompleted: true,
//           completedMessage: "Auto-generated after Enquiry Received",
//         });

//         // Proforma Accepted auto true - both sides
//         markStepComplete("Proforma Accepted", {
//           visibleTo: ["buyer", "seller"],
//           autoCompleted: true,
//           completedMessage: "Auto-accepted after Enquiry Received",
//         });
//         order.orderStatus = "Processing";
        
//         // COMMON LOGIC FOR BOTH CASH AND CREDIT
//         // Payment QR Generated - CREATE BUT DON'T COMPLETE (buyer will complete for both)
//         if (finalPaymentType === "Credit") {
//           const pay = order.paymentOption;
//           const dueDate = new Date();
//           dueDate.setDate(
//             dueDate.getDate() + (pay.creditPayment?.creditPeriodDays || 0)
//           );
//           const firstInterestDate = getNextMonthEndDate(dueDate);

//           const creditDetails = {
//             paymentType: "Credit",
//             totalAmount: order.total,
//             creditPeriodDays: pay.creditPayment.creditPeriodDays,
//             interestRatePerYear: pay.creditPayment.interestRatePerYear,
//             interestStartAfterDays: pay.creditPayment.interestStartAfterDays,
//             dueDate,
//             interestStartDate: dueDate,
//             firstInterestApplicationDate: firstInterestDate,
//             nextInterestApplicationDate: firstInterestDate,
//           };

//           createStepIfNotExists("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             creditDetails,
//             qrCodeUrl: null,
//             paymentType: "Credit",
//             awaitingBuyerAction: true,
//           });

//           order.creditPaymentDetails = creditDetails;
//         }

//         if (finalPaymentType === "Cash") {
//           // Generate QR Code for Cash payment
//           const qrCode = await generateQRCodeForPayment();
          
//           createStepIfNotExists("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             qrCodeUrl: qrCode,
//             paymentType: "Cash",
//             awaitingBuyerAction: true, // ✅ Buyer will complete this step
//           });

//           order.qrCodeData = qrCode;
//         }

//         // FOR BOTH CASH AND CREDIT - Create next steps but don't complete
//         if (finalPaymentType === "Cash" || finalPaymentType === "Credit") {
//           // Payment Received - CREATE BUT DON'T COMPLETE
//           createStepIfNotExists("Payment Received", {
//             visibleTo: ["buyer", "seller"],
//             paymentType: finalPaymentType,
//             awaitingAutoCompletion: true,
//           });

//           // Invoice Uploaded - CREATE BUT DON'T COMPLETE
//           const itemSummary = order.items.map((i) => i.productName).join(", ");
//           const totalItems = order.items.length;
//           const totalAmount = order.total;

//           createStepIfNotExists("Invoice Uploaded", {
//             visibleTo: ["buyer", "seller"],
//             invoiceSummary: { itemSummary, totalItems, totalAmount },
//             awaitingAutoCompletion: true,
//           });

//           // Dispatch - NOT auto complete (seller manually करेगा)
//           createStepIfNotExists("Dispatch", {
//             visibleTo: ["buyer", "seller"],
//             awaitingSellerAction: true,
//           });

//           // Delivered - NOT auto complete (seller manually करेगा)
//           createStepIfNotExists("Delivered", {
//             visibleTo: ["buyer", "seller"],
//             awaitingBuyerAction: true,
//           });
//         }

//         await createInvoiceOnEnquiry();
//         break;

//       case "Payment QR Generated":
//         // ✅ COMMON LOGIC FOR BOTH CASH AND CREDIT: Only buyer can complete
//         if (actionBy !== "buyer") {
//           return res.status(403).json({
//             success: false,
//             message: "Only buyer can complete Payment QR Generated step",
//           });
//         }

//         const existingStep = order.processFlow.find(
//           (s) => s.step === "Payment QR Generated"
//         );

//         // Order status set to "Processing"
//         order.orderStatus = "Processing";

//         // Complete Payment QR Generated
//         markStepComplete("Payment QR Generated", {
//           ...existingStep,
//           visibleTo: ["buyer", "seller"],
//           paymentType: finalPaymentType,
//           buyerAccepted: true,
//           acceptedAt: new Date(),
//         });

//         // AUTO COMPLETE Payment Received after Payment QR Generated (for both)
//         markStepComplete("Payment Received", {
//           visibleTo: ["buyer", "seller"],
//           paymentType: finalPaymentType,
//           autoCompleted: true,
//           message: `Auto-completed after Payment QR Generated for ${finalPaymentType.toLowerCase()} payment`,
//         });

//         // AUTO COMPLETE Invoice Uploaded after Payment QR Generated (for both)
//         const itemSummary = order.items.map((i) => i.productName).join(", ");
//         const totalItems = order.items.length;
//         const totalAmount = order.total;

//         markStepComplete("Invoice Uploaded", {
//           visibleTo: ["buyer", "seller"],
//           invoiceSummary: { itemSummary, totalItems, totalAmount },
//           autoCompleted: true,
//           message: `Auto-completed after Payment QR Generated for ${finalPaymentType.toLowerCase()} payment`,
//         });
//         break;

//       case "Payment Received":
//         // ✅ BOTH CASH AND CREDIT - Already auto-completed in Payment QR Generated
//         return res.status(400).json({
//           success: false,
//           message: `Payment Received is auto-completed for ${finalPaymentType.toLowerCase()} payments after Payment QR Generated`,
//         });
//         break;

//       case "Invoice Uploaded":
//         // ✅ BOTH CASH AND CREDIT - Already auto-completed in Payment QR Generated
//         return res.status(400).json({
//           success: false,
//           message: `Invoice Uploaded is auto-completed for ${finalPaymentType.toLowerCase()} payments after Payment QR Generated`,
//         });
//         break;

//       case "Dispatch":
//         // BOTH CREDIT AND CASH - Seller manually completes
//         if (actionBy !== "seller") {
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can dispatch order",
//           });
//         }

//         // Order status remains "Processing" during Dispatch
//         if (order.orderStatus !== "Completed") {
//           order.orderStatus = "Processing";
//         }

//         markStepComplete("Dispatch", {
//           visibleTo: ["buyer", "seller"],
//         });
//         break;

//       case "Delivered":
//         // BOTH CREDIT AND CASH - Buyer manually completes
//         if (actionBy !== "buyer") {
//           return res.status(403).json({
//             success: false,
//             message: "Only buyer can mark as delivered",
//           });
//         }

//         // Order status set to "Completed"
//         order.orderStatus = "Completed";

//         markStepComplete("Delivered", {
//           visibleTo: ["buyer", "seller"],
//         });
//         break;

//       // Add a case for Cancelled order
//       case "Cancelled":
//         // Either seller or buyer can cancel order
//         if (!["seller", "buyer"].includes(actionBy)) {
//           return res.status(403).json({
//             success: false,
//             message: "Only seller or buyer can cancel order",
//           });
//         }

//         // Order status set to "Cancelled"
//         order.orderStatus = "Cancelled";

//         // Mark all steps as cancelled
//         const cancelledSteps = [
//           "Enquiry Received",
//           "Proforma Invoice",
//           "Proforma Accepted",
//           "Payment QR Generated",
//           "Payment Received",
//           "Invoice Uploaded",
//           "Dispatch",
//           "Delivered",
//         ];

//         cancelledSteps.forEach((stepName) => {
//           const stepObj = order.processFlow.find((s) => s.step === stepName);
//           if (stepObj) {
//             stepObj.cancelled = true;
//             stepObj.cancelledAt = new Date();
//             stepObj.cancelledBy = actionBy;
//             stepObj.completed = false;
//           }
//         });

//         // Add a cancelled step to process flow
//         markStepComplete("Order Cancelled", {
//           visibleTo: ["buyer", "seller"],
//           cancelled: true,
//           cancelledBy: actionBy,
//           cancelledAt: new Date(),
//           reason: req.body.reason || "Order cancelled by " + actionBy,
//         });
//         break;

//       default:
//         return res
//           .status(400)
//           .json({ success: false, message: "Invalid step" });
//     }

//     await order.save();

//     res.status(200).json({
//       success: true,
//       message: `${step} marked as completed.`,
//       paymentTypeUsed: finalPaymentType,
//       data: order,
//     });
//   } catch (err) {
//     return next(new ErrorHandler(err.message, 500));
//   }
// };

export const updateOrderProcessStep = async (req, res, next) => {
  try {
    const { orderId, step, actionBy } = req.body;

    if (!mongoose.Types.ObjectId.isValid(orderId))
      return next(new ErrorHandler("Invalid Order ID", 400));

    const order = await Order.findById(orderId)
      .populate("paymentOption")
      .populate({
        path: "items.seller",
        select: "name email bankDetails accountName upiId",
        populate: {
          path: "bankDetails",
          select:
            "bankName accountName upiId accountNumber ifscCode branchName branchAddress",
        },
      })
      .populate("buyer");

    if (!order)
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });

    const finalPaymentType = getFinalPaymentType(order.paymentOption, order);

    if (!finalPaymentType)
      return next(new ErrorHandler("Unable to determine payment type", 400));

    const markStepComplete = (stepName, extraData = {}) => {
      let stepObj = order.processFlow.find((s) => s.step === stepName);
      if (!stepObj) {
        order.processFlow.push({
          step: stepName,
          completed: true,
          completedAt: new Date(),
          ...extraData,
        });
      } else {
        stepObj.completed = true;
        stepObj.completedAt = new Date();
        Object.assign(stepObj, extraData);
      }
    };

    const createStepIfNotExists = (stepName, extraData = {}) => {
      let stepObj = order.processFlow.find((s) => s.step === stepName);
      if (!stepObj) {
        order.processFlow.push({
          step: stepName,
          completed: false,
          ...extraData,
        });
      } else {
        Object.keys(extraData).forEach((key) => {
          stepObj[key] = extraData[key];
        });
      }
    };

    // UPDATED INVOICE CREATION LOGIC FOR CREDIT
    const createInvoiceOnEnquiry = async () => {
      const existing = await Invoice.findOne({ order: order._id });
      if (existing) return;

      if (!order.paymentOption)
        throw new Error("Payment Option not found for this order");

      let invoiceData = {
        order: order._id,
        buyer: order.buyer._id,
        seller: order.items[0]?.seller?._id,
        amount: order.total,
        status: "Pending",
        bankStatement: [],
        paymentType: finalPaymentType,
      };

      // CASH → INVOICE PAID
      if (finalPaymentType === "Cash") {
        invoiceData.status = "Paid";
        invoiceData.paidAt = new Date();

        invoiceData.bankStatement.push({
          date: new Date(),
          description: "Cash Payment Received",
          debit: 0,
          credit: order.total,
          balance: 0,
        });
      }

      // CREDIT → CREDIT TERMS WITH CORRECT LOGIC
      if (finalPaymentType === "Credit") {
        const pay = order.paymentOption;

        invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
        invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
        invoiceData.interestStartAfterDays =
          pay.creditPayment.interestStartAfterDays;

        // Calculate dueDate (invoice date + creditPeriodDays)
        const invoiceDate = new Date();
        const dueDate = new Date(invoiceDate);
        dueDate.setDate(dueDate.getDate() + pay.creditPayment.creditPeriodDays);
        invoiceData.dueDate = dueDate;

        // CORRECTION: interestAccrualStartDate = dueDate (not dueDate + interestStartAfterDays)
        // Because interest starts immediately after due date
        invoiceData.interestAccrualStartDate = dueDate;

        // Store interestStartAfterDays for reference (30 days)
        // This is the grace period before interest actually accrues
        invoiceData.gracePeriodDays = pay.creditPayment.interestStartAfterDays;

        // First interest application will be on next month-end after dueDate
        const firstInterestDate = getNextMonthEndDate(dueDate);
        invoiceData.nextInterestApplicationDate = firstInterestDate;

        // Initial bank statement entry
        invoiceData.bankStatement.push({
          date: new Date(),
          description: "Invoice Created (Credit)",
          debit: order.total,
          credit: 0,
          balance: order.total,
          paymentStatus: "Approved",
        });
      }

      await Invoice.create(invoiceData);
    };

    const generateQRCodeForPayment = async () => {
      const sellerBank = order.items[0]?.seller?.bankDetails;

      if (!sellerBank?.upiId) throw new Error("Seller UPI ID not found.");

      if (finalPaymentType === "Cash") {
        return await generateQRCode(sellerBank.upiId, order.total);
      }

      return null;
    };

    switch (step) {
      case "Enquiry Received":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can send Enquiry Received",
          });

        // Seller Enquiry Received complete करते ही
        markStepComplete("Enquiry Received", {
          visibleTo: ["buyer", "seller"],
        });

        // Order status set to "Pending"
        order.orderStatus = "Pending";

        // Proforma Invoice auto true - both sides
        markStepComplete("Proforma Invoice", {
          visibleTo: ["buyer", "seller"],
          autoCompleted: true,
          completedMessage: "Auto-generated after Enquiry Received",
        });

        // Proforma Accepted auto true - both sides
        markStepComplete("Proforma Accepted", {
          visibleTo: ["buyer", "seller"],
          autoCompleted: true,
          completedMessage: "Auto-accepted after Enquiry Received",
        });
        order.orderStatus = "Processing";
        
        // COMMON LOGIC FOR BOTH CASH AND CREDIT
        // Payment QR Generated - CREATE BUT DON'T COMPLETE (buyer will complete for both)
        if (finalPaymentType === "Credit") {
          const pay = order.paymentOption;
          const dueDate = new Date();
          dueDate.setDate(
            dueDate.getDate() + (pay.creditPayment?.creditPeriodDays || 0)
          );
          const firstInterestDate = getNextMonthEndDate(dueDate);

          const creditDetails = {
            paymentType: "Credit",
            totalAmount: order.total,
            creditPeriodDays: pay.creditPayment.creditPeriodDays,
            interestRatePerYear: pay.creditPayment.interestRatePerYear,
            interestStartAfterDays: pay.creditPayment.interestStartAfterDays,
            dueDate,
            interestStartDate: dueDate,
            firstInterestApplicationDate: firstInterestDate,
            nextInterestApplicationDate: firstInterestDate,
          };

          createStepIfNotExists("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            creditDetails,
            qrCodeUrl: null,
            paymentType: "Credit",
            awaitingBuyerAction: true,
          });

          order.creditPaymentDetails = creditDetails;
        }

        if (finalPaymentType === "Cash") {
          // Generate QR Code for Cash payment
          const qrCode = await generateQRCodeForPayment();
          
          createStepIfNotExists("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            qrCodeUrl: qrCode,
            paymentType: "Cash",
            awaitingBuyerAction: true, // ✅ Buyer will complete this step
          });

          order.qrCodeData = qrCode;
        }

        // FOR BOTH CASH AND CREDIT - Create next steps but don't complete
        if (finalPaymentType === "Cash" || finalPaymentType === "Credit") {
          // ✅ IMPORTANT CHANGE: Payment Received - DIFFERENT LOGIC FOR CASH AND CREDIT
          createStepIfNotExists("Payment Received", {
            visibleTo: ["buyer", "seller"],
            paymentType: finalPaymentType,
            // CASH: Seller manually complete karega
            // CREDIT: Auto-complete hoga
            ...(finalPaymentType === "Cash" 
              ? { awaitingSellerAction: true }  // ✅ Cash mein seller manually mark karega
              : { awaitingAutoCompletion: true } // ✅ Credit mein auto-complete
            ),
          });

          // Invoice Uploaded - CREATE BUT DON'T COMPLETE
          const itemSummary = order.items.map((i) => i.productName).join(", ");
          const totalItems = order.items.length;
          const totalAmount = order.total;

          createStepIfNotExists("Invoice Uploaded", {
            visibleTo: ["buyer", "seller"],
            invoiceSummary: { itemSummary, totalItems, totalAmount },
            awaitingAutoCompletion: true,
          });

          // Dispatch - NOT auto complete (seller manually करेगा)
          createStepIfNotExists("Dispatch", {
            visibleTo: ["buyer", "seller"],
            awaitingSellerAction: true,
          });

          // Delivered - NOT auto complete (seller manually करेगा)
          createStepIfNotExists("Delivered", {
            visibleTo: ["buyer", "seller"],
            awaitingBuyerAction: true,
          });
        }

        await createInvoiceOnEnquiry();
        break;

      case "Payment QR Generated":
        // ✅ COMMON LOGIC FOR BOTH CASH AND CREDIT: Only buyer can complete
        if (actionBy !== "buyer") {
          return res.status(403).json({
            success: false,
            message: "Only buyer can complete Payment QR Generated step",
          });
        }

        const existingStep = order.processFlow.find(
          (s) => s.step === "Payment QR Generated"
        );

        // Order status set to "Processing"
        order.orderStatus = "Processing";

        // Complete Payment QR Generated
        markStepComplete("Payment QR Generated", {
          ...existingStep,
          visibleTo: ["buyer", "seller"],
          paymentType: finalPaymentType,
          buyerAccepted: true,
          acceptedAt: new Date(),
        });

        // ✅ CREDIT: AUTO COMPLETE Payment Received after Payment QR Generated
        if (finalPaymentType === "Credit") {
          markStepComplete("Payment Received", {
            visibleTo: ["buyer", "seller"],
            paymentType: finalPaymentType,
            autoCompleted: true,
            message: `Auto-completed after Payment QR Generated for Credit payment`,
          });
        }

        // ✅ CASH: Payment Received NOT auto-complete - Seller manually mark karega
        if (finalPaymentType === "Cash") {
          // Find Payment Received step and mark as awaiting seller action
          const paymentReceivedStep = order.processFlow.find(
            (s) => s.step === "Payment Received"
          );
          
          if (paymentReceivedStep) {
            paymentReceivedStep.awaitingSellerAction = true;
            paymentReceivedStep.paymentType = "Cash";
          }
        }

        // AUTO COMPLETE Invoice Uploaded after Payment QR Generated (for both)
        const itemSummary = order.items.map((i) => i.productName).join(", ");
        const totalItems = order.items.length;
        const totalAmount = order.total;

        markStepComplete("Invoice Uploaded", {
          visibleTo: ["buyer", "seller"],
          invoiceSummary: { itemSummary, totalItems, totalAmount },
          autoCompleted: true,
          message: `Auto-completed after Payment QR Generated for ${finalPaymentType.toLowerCase()} payment`,
        });
        break;

      case "Payment Received":
        // ✅ CASH: Only seller can complete Payment Received
        if (finalPaymentType === "Cash") {
          if (actionBy !== "seller") {
            return res.status(403).json({
              success: false,
              message: "Only seller can mark Payment Received for Cash payment",
            });
          }

          // Check if Payment QR Generated is completed first
          const paymentQRStep = order.processFlow.find(
            (s) => s.step === "Payment QR Generated" && s.completed
          );
          
          if (!paymentQRStep) {
            return res.status(400).json({
              success: false,
              message: "Please complete Payment QR Generated first",
            });
          }

          // Mark Payment Received as complete
          markStepComplete("Payment Received", {
            visibleTo: ["buyer", "seller"],
            paymentType: "Cash",
            paymentConfirmedBySeller: true,
            confirmedAt: new Date(),
            paymentMethod: "Cash",
            paymentReference: req.body.paymentReference || "Cash Payment",
          });

          // Update order status
          order.orderStatus = "Processing";
        }
        
        // ✅ CREDIT: Already auto-completed in Payment QR Generated
        else if (finalPaymentType === "Credit") {
          return res.status(400).json({
            success: false,
            message: `Payment Received is auto-completed for Credit payments after Payment QR Generated`,
          });
        }
        break;

      case "Invoice Uploaded":
        // ✅ BOTH CASH AND CREDIT - Already auto-completed in Payment QR Generated
        return res.status(400).json({
          success: false,
          message: `Invoice Uploaded is auto-completed for ${finalPaymentType.toLowerCase()} payments after Payment QR Generated`,
        });
        break;

      case "Dispatch":
        // BOTH CREDIT AND CASH - Seller manually completes
        if (actionBy !== "seller") {
          return res.status(403).json({
            success: false,
            message: "Only seller can dispatch order",
          });
        }

        // Check if Payment Received is completed first (for Cash)
        if (finalPaymentType === "Cash") {
          const paymentReceivedStep = order.processFlow.find(
            (s) => s.step === "Payment Received" && s.completed
          );
          
          if (!paymentReceivedStep) {
            return res.status(400).json({
              success: false,
              message: "Please complete Payment Received first for Cash payment",
            });
          }
        }

        // Order status remains "Processing" during Dispatch
        if (order.orderStatus !== "Completed") {
          order.orderStatus = "Processing";
        }

        markStepComplete("Dispatch", {
          visibleTo: ["buyer", "seller"],
        });
        break;

      case "Delivered":
        // BOTH CREDIT AND CASH - Buyer manually completes
        if (actionBy !== "buyer") {
          return res.status(403).json({
            success: false,
            message: "Only buyer can mark as delivered",
          });
        }

        // Order status set to "Completed"
        order.orderStatus = "Completed";

        markStepComplete("Delivered", {
          visibleTo: ["buyer", "seller"],
        });
        break;

      // Add a case for Cancelled order
      case "Cancelled":
        // Either seller or buyer can cancel order
        if (!["seller", "buyer"].includes(actionBy)) {
          return res.status(403).json({
            success: false,
            message: "Only seller or buyer can cancel order",
          });
        }

        // Order status set to "Cancelled"
        order.orderStatus = "Cancelled";

        // Mark all steps as cancelled
        const cancelledSteps = [
          "Enquiry Received",
          "Proforma Invoice",
          "Proforma Accepted",
          "Payment QR Generated",
          "Payment Received",
          "Invoice Uploaded",
          "Dispatch",
          "Delivered",
        ];

        cancelledSteps.forEach((stepName) => {
          const stepObj = order.processFlow.find((s) => s.step === stepName);
          if (stepObj) {
            stepObj.cancelled = true;
            stepObj.cancelledAt = new Date();
            stepObj.cancelledBy = actionBy;
            stepObj.completed = false;
          }
        });

        // Add a cancelled step to process flow
        markStepComplete("Order Cancelled", {
          visibleTo: ["buyer", "seller"],
          cancelled: true,
          cancelledBy: actionBy,
          cancelledAt: new Date(),
          reason: req.body.reason || "Order cancelled by " + actionBy,
        });
        break;

      default:
        return res
          .status(400)
          .json({ success: false, message: "Invalid step" });
    }

    await order.save();

    res.status(200).json({
      success: true,
      message: `${step} marked as completed.`,
      paymentTypeUsed: finalPaymentType,
      data: order,
    });
  } catch (err) {
    return next(new ErrorHandler(err.message, 500));
  }
};
// Update Order Items
export const updateOrderItem = async (req, res, next) => {
  try {
    const { orderId, items } = req.body;

    if (!orderId || !items?.length) {
      return res.status(400).json({
        success: false,
        message: "orderId and items array are required",
      });
    }

    const order = await Order.findById(orderId);
    if (!order)
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });

    let newSubTotal = 0;
    order.items.forEach((item) => {
      const reqItem = items.find((i) => i.itemId === item._id.toString());
      if (!reqItem) return;

      const qty = reqItem.quantity;
      item.quantity = qty;

      const perUnitFinal = (item.discountPrice || 0) + (item.gstAmount || 0);

      const updatedFinal = perUnitFinal * qty;
      item.finalPrice = Number(updatedFinal.toFixed(2));

      newSubTotal += item.finalPrice;
    });
    const oldSubTotal = order.subTotal || 1;
    const oldDiscount = order.discountFromPayment || 0;

    const discountRatio = oldDiscount / oldSubTotal;
    const newDiscount = newSubTotal * discountRatio;
    order.subTotal = Number(newSubTotal.toFixed(2));
    order.discountFromPayment = Number(newDiscount.toFixed(2));
    order.total = Number(
      (order.subTotal - order.discountFromPayment).toFixed(2)
    );

    await order.save();

    return res.status(200).json({
      success: true,
      message: "Order items updated successfully",
      order,
    });
  } catch (error) {
    return next(new ErrorHandler(error.message, 500));
  }
};

// Function to get invoice details for an order
export const getOrderInvoice = catchAsyncErrors(async (req, res, next) => {
  const { orderId } = req.params;

  const invoice = await Invoice.findOne({ order: orderId })
    .populate("order")
    .populate("buyer")
    .populate("seller");

  if (!invoice) {
    return next(new ErrorHandler("Invoice not found for this order", 404));
  }

  // Calculate latest balance
  const latestBalance = invoice.bankStatement.at(-1)?.balance ?? invoice.amount;

  res.status(200).json({
    success: true,
    data: {
      invoice,
      latestBalance,
      // Add next interest date for credit invoices
      nextInterestDate:
        invoice.nextInterestApplicationDate ||
        (invoice.dueDate ? getNextMonthEndDate(invoice.dueDate) : null),
    },
  });
});
