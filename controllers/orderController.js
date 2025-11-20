import mongoose from "mongoose";
import Order from "../models/orderModel.js";
import Cart from "../models/cartModel.js";
import Invoice from "../models/invoiceModel.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import ErrorHandler from "../utils/Errorhandler.js";
import { generateQRCode } from "../utils/generateQRCode.js";
import Product from "../models/sellerProductModel.js";
import User from "../models/userModel.js";
import PaymentOption from "../models/paymentOption.js";

// Create Order
// export const createOrder = async (req, res) => {
//   try {
//     const cart = await Cart.findOne({ user: req.user.id })
//       .populate("items.product")
//       .populate("user");

//     if (!cart) {
//       return res
//         .status(404)
//         .json({ success: false, message: "Cart not found" });
//     }

//     // Default process flow
//     const defaultSteps = [
//       { step: "Enquiry Received", completed: true, completedAt: new Date() },
//       { step: "Proforma Invoice" },
//       { step: "Proforma Accepted" },
//       { step: "Payment Received" },
//       { step: "Invoice Uploaded" },
//       { step: "Dispatch" },
//       { step: "Delivered" },
//     ];

//     // Create order
//     const newOrder = await Order.create({
//       buyer: cart.user._id,
//       items: cart.items.map((i) => ({
//         product: i.product._id,
//         name: i.product.name,
//         image: i.product.image,
//         price: i.product.price,
//         mrp: i.mrp,
//         quantity: i.quantity,
//         discountPrice: i.discountPrice,
//         gstAmount: i.gstAmount,
//         finalPrice: i.finalPrice,
//         // Save sellerId from product
//         seller: i.product.user,
//       })),
//       subTotal: cart.subTotal,
//       discountFromPayment: cart.discountFromPayment,
//       total: cart.total,
//       paymentOption: cart.paymentOption?._id,
//       processFlow: defaultSteps,
//     });

//     const order = await Order.findById(newOrder._id)
//       .populate("buyer", "name mode")
//       .populate({
//         path: "items.seller",
//         select: "name mode",
//       });
//     // (Optional) Empty cart after order
//     await Cart.findByIdAndDelete(cart._id);

//     res.status(201).json({ success: true, message: "Order created", order });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ success: false, message: "Server Error" });
//   }
// };

// export const createOrder = async (req, res) => {
//   try {
//     const { seller } = req.body;
//     if (!seller) {
//       return res.status(400).json({
//         success: false,
//         message: "Seller ID is required to create order",
//       });
//     }

//     const cart = await Cart.findOne({ user: req.user.id, seller })
//       .populate("items.product")
//       .populate("user");

//     if (!cart || !cart.items.length) {
//       return res.status(404).json({
//         success: false,
//         message: "Cart not found or empty",
//       });
//     }

//     console.log("Cart found:", cart);

//     // 🧮 Calculate subTotal and total manually
//     let subTotal = 0;
//     let total = 0;

//     cart.items.forEach((item) => {
//       const basePrice = item?.product?.price || item?.mrp || 0;
//       const gstPercent = item?.product?.category?.gst || 0;
//       const gstAmount = (basePrice * gstPercent) / 100;
//       const priceWithGst = basePrice + gstAmount;

//       subTotal += basePrice * item.quantity;
//       total += priceWithGst * item.quantity;
//     });

//     // Default process flow
//     const defaultSteps = [
//       { step: "Enquiry Received", completed: true, completedAt: new Date() },
//       { step: "Proforma Invoice" },
//       { step: "Proforma Accepted" },
//       { step: "Payment Received" },
//       { step: "Invoice Uploaded" },
//       { step: "Dispatch" },
//       { step: "Delivered" },
//     ];

//     // 🧾 Create order
//     const newOrder = await Order.create({
//       buyer: cart.user._id,
//       items: cart.items.map((i) => ({
//         product: i.product._id,
//         name: i.product.name,
//         image: i.product.image,
//         price: i.product.price || i.mrp || 0,
//         mrp: i.mrp,
//         quantity: i.quantity,
//         discountPrice: i.discountPrice,
//         gstAmount: i.gstAmount,
//         finalPrice: i.finalPrice,
//         seller: i.product.user,
//       })),
//       subTotal,
//       discountFromPayment: cart.discountFromPayment || 0,
//       total,
//       paymentOption: cart.paymentOption?._id,
//       processFlow: defaultSteps,
//     });

//     const order = await Order.findById(newOrder._id)
//       .populate("buyer", "name mode")
//       .populate({
//         path: "items.seller",
//         select: "name mode",
//       });

//     // 🧹 Empty cart after order
//     await Cart.findByIdAndDelete(cart._id);

//     res.status(201).json({
//       success: true,
//       message: "Order created successfully",
//       order,
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({
//       success: false,
//       message: "Server Error",
//     });
//   }
// };

export const createOrder = async (req, res) => {
  try {
    const { seller } = req.body;
    if (!seller) {
      return res.status(400).json({
        success: false,
        message: "Seller ID is required to create order",
      });
    }

    // Find cart for this user & seller
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

    // Default process flow
    const defaultSteps = [
      // { step: "Enquiry Received", completed: true, completedAt: new Date() },
      { step: "Enquiry Received" },
      { step: "Proforma Invoice" },
      { step: "Proforma Accepted" },
      { step: "Payment QR Generated" },
      { step: "Payment Received" },
      { step: "Invoice Uploaded" },
      { step: "Dispatch" },
      { step: "Delivered" },
    ];

    // Create order using existing cart data
    const newOrder = await Order.create({
      buyer: cart.user._id,
      seller: cart.seller,
      items: cart.items.map((i) => ({
        product: i.product._id,
        name: i.product.name,
        image: i.product.image,
        price: i.product.price || i.mrp || 0,
        mrp: i.mrp,
        quantity: i.quantity,
        discountPrice: i.discountPrice,
        gstAmount: i.gstAmount,
        finalPrice: i.finalPrice,
        seller: i.product.user,
      })),
      subTotal: cart.subTotal || 0,
      discountFromPayment: cart.discountFromPayment || 0,
      total: cart.total || 0,
      paymentOption: cart.paymentOption?._id,
      processFlow: defaultSteps,
    });

    // Populate to send a cleaner response
    const order = await Order.findById(newOrder._id)
      .populate("buyer", "name mode")
      .populate({
        path: "items.seller",
        select: "name mode",
      });

    // Clear cart after order creation
    await Cart.findByIdAndDelete(cart._id);

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      order,
    });
  } catch (error) {
    console.error("createOrder error:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
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
    // .sort({ date: -1 });
    .sort({ createdAt: -1 });

  res.status(200).json({
    success: true,
    orders,
  });
});

// Get Seller Orders
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

// Update Order Status
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

// Update Order Process Step (Seller Restricted)
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
    (i) => i.seller.toString() === sellerId.toString()
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

// Update order process step (buyer/seller actions)
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

//     // INVOICE CREATION FUNCTION
//     const createInvoiceOnEnquiry = async () => {
//       // Check if invoice already exists
//       const existing = await Invoice.findOne({ order: order._id });
//       if (existing) {
//         console.log("Invoice already exists. Skipping creation.");
//         return;
//       }

//       if (!order.paymentOption)
//         throw new Error("Payment Option not found for this order");

//       const pay = order.paymentOption;

//       let invoiceData = {
//         order: order._id,
//         buyer: order.buyer._id,
//         seller: order.items[0]?.seller?._id,
//         amount: order.total,
//         status: "Pending",
//         bankStatement: [],
//       };

//       // If Cash → Mark invoice paid
//       if (pay.paymentType === "Cash") {
//         invoiceData.status = "Paid";
//         invoiceData.paidAt = new Date();

//         // Add bank statement entry
//         invoiceData.bankStatement.push({
//           date: new Date(),
//           description: "Cash Payment Received",
//           debit: 0,
//           credit: order.total,
//           balance: 0,
//         });
//       } else if (pay.paymentType === "Credit") {
//         // Add credit related values
//         invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
//         invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
//         invoiceData.interestStartAfterDays =
//           pay.creditPayment.interestStartAfterDays;

//         // Due date = Today + creditPeriodDays
//         const dueDate = new Date();
//         dueDate.setDate(dueDate.getDate() + pay.creditPayment.creditPeriodDays);
//         invoiceData.dueDate = dueDate;

//         // Interest accrual start date = dueDate + interestStartAfterDays
//         const interestStart = new Date(dueDate);
//         interestStart.setDate(
//           interestStart.getDate() + pay.creditPayment.interestStartAfterDays
//         );
//         invoiceData.interestAccrualStartDate = interestStart;
//       }

//       // SAVE the invoice
//       await Invoice.create(invoiceData);
//     };

//     // ---------------------------------------------
//     // MAIN STEP LOGIC
//     // ---------------------------------------------
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

//         // CREATE INVOICE IMMEDIATELY
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

//       // case "Proforma Accepted":
//       //   if (actionBy !== "buyer")
//       //     return res
//       //       .status(403)
//       //       .json({
//       //         success: false,
//       //         message: "Only buyer can accept Proforma",
//       //       });

//       //   markStepComplete("Proforma Accepted", {
//       //     visibleTo: ["buyer", "seller"],
//       //   });

//       //   const paymentOption = order.paymentOption;

//       //   if (!paymentOption)
//       //     return res
//       //       .status(400)
//       //       .json({ success: false, message: "Payment option missing." });

//       //   const sellerBank = order.items[0]?.seller?.bankDetails;
//       //   if (!sellerBank?.upiId)
//       //     return res
//       //       .status(400)
//       //       .json({ success: false, message: "Seller UPI ID not found." });

//       //   const qrCode = await generateQRCode(sellerBank.upiId, order.total);

//       //   markStepComplete("Payment QR Generated", {
//       //     visibleTo: ["buyer", "seller"],
//       //     qrCodeUrl: qrCode,
//       //   });

//       //   order.qrCodeData = qrCode;
//       //   break;

//       case "Proforma Accepted":
//         if (actionBy !== "buyer")
//           return res.status(403).json({
//             success: false,
//             message: "Only buyer can accept Proforma",
//           });

//         markStepComplete("Proforma Accepted", {
//           visibleTo: ["buyer", "seller"],
//         });

//         // ---- Fetch Full Payment Option Document ----
//         const paymentOptionFull = await PaymentOption.findById(
//           order.paymentOption
//         );

//         if (!paymentOptionFull)
//           return res.status(400).json({
//             success: false,
//             message: "Payment option not found",
//           });

//         // -------------------------------
//         // 🔵 CASE 1: CASH → Auto QR Generate
//         // -------------------------------
//         if (paymentOptionFull.paymentType === "Cash") {
//           const sellerBank = order.items[0]?.seller?.bankDetails;

//           if (!sellerBank?.upiId) {
//             return res.status(400).json({
//               success: false,
//               message: "Seller UPI ID not found for QR Code",
//             });
//           }

//           const qrCode = await generateQRCode(sellerBank.upiId, order.total);

//           markStepComplete("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             qrCodeUrl: qrCode,
//             paymentType: "Cash",
//           });

//           order.qrCodeData = qrCode;
//         }

//         // -------------------------------
//         // 🔵 CASE 2: CREDIT → Return Credit Details (NO QR)
//         // -------------------------------
//         else if (paymentOptionFull.paymentType === "Credit") {
//           const credit = paymentOptionFull.creditPayment;

//           if (!credit) {
//             return res.status(400).json({
//               success: false,
//               message: "Credit payment data not found",
//             });
//           }

//           markStepComplete("Credit Details Shared", {
//             visibleTo: ["buyer", "seller"],
//             paymentType: "Credit",
//             creditDetails: {
//               creditPeriodDays: credit.creditPeriodDays,
//               interestRatePerYear: credit.interestRatePerYear,
//               interestStartAfterDays: credit.interestStartAfterDays,
//             },
//           });
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

//         markStepComplete("Delivered", { visibleTo: ["buyer", "seller"] });
//         break;

//       default:
//         return res
//           .status(400)
//           .json({ success: false, message: "Invalid step" });
//     }

//     // Save Order
//     await order.save();

//     res.status(200).json({
//       success: true,
//       message: `${step} marked as completed.`,
//       data: order,
//     });
//   } catch (err) {
//     console.error("Error in updateOrderProcessStep:", err);
//     res.status(500).json({
//       success: false,
//       message: "Server error",
//       error: err.message,
//     });
//   }
// };

// Update order process step (buyer/seller actions)
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

//     // INVOICE CREATION FUNCTION
//     const createInvoiceOnEnquiry = async () => {
//       // Check if invoice already exists
//       const existing = await Invoice.findOne({ order: order._id });
//       if (existing) {
//         console.log("Invoice already exists. Skipping creation.");
//         return;
//       }

//       if (!order.paymentOption)
//         throw new Error("Payment Option not found for this order");

//       const pay = order.paymentOption;

//       let invoiceData = {
//         order: order._id,
//         buyer: order.buyer._id,
//         seller: order.items[0]?.seller?._id,
//         amount: order.total,
//         status: "Pending",
//         bankStatement: [],
//       };

//       // If Cash → Mark invoice paid
//       if (pay.paymentType === "Cash") {
//         invoiceData.status = "Paid";
//         invoiceData.paidAt = new Date();

//         // Add bank statement entry
//         invoiceData.bankStatement.push({
//           date: new Date(),
//           description: "Cash Payment Received",
//           debit: 0,
//           credit: order.total,
//           balance: 0,
//         });
//       } else if (pay.paymentType === "Credit") {
//         // Add credit related values
//         invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
//         invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
//         invoiceData.interestStartAfterDays =
//           pay.creditPayment.interestStartAfterDays;

//         // Due date = Today + creditPeriodDays
//         const dueDate = new Date();
//         dueDate.setDate(dueDate.getDate() + pay.creditPayment.creditPeriodDays);
//         invoiceData.dueDate = dueDate;

//         // Interest accrual start date = dueDate + interestStartAfterDays
//         const interestStart = new Date(dueDate);
//         interestStart.setDate(
//           interestStart.getDate() + pay.creditPayment.interestStartAfterDays
//         );
//         invoiceData.interestAccrualStartDate = interestStart;
//       }

//       // SAVE the invoice
//       await Invoice.create(invoiceData);
//     };

//     // QR CODE GENERATION FUNCTION
//     const generateQRCodeForPayment = async () => {
//       const paymentOption = order.paymentOption;

//       if (!paymentOption) {
//         throw new Error("Payment option missing.");
//       }

//       const sellerBank = order.items[0]?.seller?.bankDetails;
//       if (!sellerBank?.upiId) {
//         throw new Error("Seller UPI ID not found.");
//       }

//       // Generate QR code only for Cash payments
//       if (paymentOption.paymentType === "Cash") {
//         const qrCode = await generateQRCode(sellerBank.upiId, order.total);
//         return qrCode;
//       }

//       // For Credit payments, return null (no QR code)
//       return null;
//     };

//     // ---------------------------------------------
//     // MAIN STEP LOGIC
//     // ---------------------------------------------
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

//         // CREATE INVOICE IMMEDIATELY
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

//         markStepComplete("Proforma Accepted", {
//           visibleTo: ["buyer", "seller"],
//         });

//         const paymentOption = order.paymentOption;

//         if (!paymentOption) {
//           return res.status(400).json({
//             success: false,
//             message: "Payment option missing."
//           });
//         }

//         // For Cash payments: Generate QR code
//         if (paymentOption.paymentType === "Cash") {
//           try {
//             const qrCode = await generateQRCodeForPayment();

//             markStepComplete("Payment QR Generated", {
//               visibleTo: ["buyer", "seller"],
//               qrCodeUrl: qrCode,
//             });

//             order.qrCodeData = qrCode;
//           } catch (qrError) {
//             return res.status(400).json({
//               success: false,
//               message: `QR Code generation failed: ${qrError.message}`,
//             });
//           }
//         }
//         // For Credit payments: Store credit details for display
//         else if (paymentOption.paymentType === "Credit") {
//           const creditDetails = {
//             creditPeriodDays: paymentOption.creditPayment?.creditPeriodDays || 0,
//             interestRatePerYear: paymentOption.creditPayment?.interestRatePerYear || 0,
//             interestStartAfterDays: paymentOption.creditPayment?.interestStartAfterDays || 0,
//             paymentType: "Credit"
//           };

//           markStepComplete("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             creditDetails: creditDetails,
//             qrCodeUrl: null, // No QR code for credit
//             autoComplete: false,
//           });

//           order.creditPaymentDetails = creditDetails;
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

//         markStepComplete("Delivered", { visibleTo: ["buyer", "seller"] });
//         break;

//       default:
//         return res.status(400).json({ success: false, message: "Invalid step" });
//     }

//     // Save Order
//     await order.save();

//     res.status(200).json({
//       success: true,
//       message: `${step} marked as completed.`,
//       data: order,
//     });
//   } catch (err) {
//     console.error("Error in updateOrderProcessStep:", err);
//     res.status(500).json({
//       success: false,
//       message: "Server error",
//       error: err.message,
//     });
//   }
// };

// Update order process step (buyer/seller actions)
// Update order process step (buyer/seller actions)
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

//     // Helper function for creating step without marking complete
//     const createStepIfNotExists = (stepName, extraData = {}) => {
//       let stepObj = order.processFlow.find((s) => s.step === stepName);
//       if (!stepObj) {
//         order.processFlow.push({
//           step: stepName,
//           completed: false,
//           ...extraData,
//         });
//       } else {
//         // Update existing step with new data
//         Object.keys(extraData).forEach(key => {
//           stepObj[key] = extraData[key];
//         });
//       }
//     };

//     // INVOICE CREATION FUNCTION
//     const createInvoiceOnEnquiry = async () => {
//       // Check if invoice already exists
//       const existing = await Invoice.findOne({ order: order._id });
//       if (existing) {
//         console.log("Invoice already exists. Skipping creation.");
//         return;
//       }

//       if (!order.paymentOption)
//         throw new Error("Payment Option not found for this order");

//       const pay = order.paymentOption;

//       let invoiceData = {
//         order: order._id,
//         buyer: order.buyer._id,
//         seller: order.items[0]?.seller?._id,
//         amount: order.total,
//         status: "Pending",
//         bankStatement: [],
//       };

//       // If Cash → Mark invoice paid
//       if (pay.paymentType === "Cash") {
//         invoiceData.status = "Paid";
//         invoiceData.paidAt = new Date();

//         // Add bank statement entry
//         invoiceData.bankStatement.push({
//           date: new Date(),
//           description: "Cash Payment Received",
//           debit: 0,
//           credit: order.total,
//           balance: 0,
//         });
//       } else if (pay.paymentType === "Credit") {
//         // Add credit related values
//         invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
//         invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
//         invoiceData.interestStartAfterDays =
//           pay.creditPayment.interestStartAfterDays;

//         // Due date = Today + creditPeriodDays
//         const dueDate = new Date();
//         dueDate.setDate(dueDate.getDate() + pay.creditPayment.creditPeriodDays);
//         invoiceData.dueDate = dueDate;

//         // Interest accrual start date = dueDate + interestStartAfterDays
//         const interestStart = new Date(dueDate);
//         interestStart.setDate(
//           interestStart.getDate() + pay.creditPayment.interestStartAfterDays
//         );
//         invoiceData.interestAccrualStartDate = interestStart;
//       }

//       // SAVE the invoice
//       await Invoice.create(invoiceData);
//     };

//     // QR CODE GENERATION FUNCTION
//     const generateQRCodeForPayment = async () => {
//       const paymentOption = order.paymentOption;

//       if (!paymentOption) {
//         throw new Error("Payment option missing.");
//       }

//       const sellerBank = order.items[0]?.seller?.bankDetails;
//       if (!sellerBank?.upiId) {
//         throw new Error("Seller UPI ID not found.");
//       }

//       // Generate QR code only for Cash payments
//       if (paymentOption.paymentType === "Cash") {
//         const qrCode = await generateQRCode(sellerBank.upiId, order.total);
//         return qrCode;
//       }

//       // For Credit payments, return null (no QR code)
//       return null;
//     };

//     // ---------------------------------------------
//     // MAIN STEP LOGIC
//     // ---------------------------------------------
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

//         // CREATE INVOICE IMMEDIATELY
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

//         markStepComplete("Proforma Accepted", {
//           visibleTo: ["buyer", "seller"],
//         });

//         const paymentOption = order.paymentOption;

//         if (!paymentOption) {
//           return res.status(400).json({
//             success: false,
//             message: "Payment option missing."
//           });
//         }

//         // For Cash payments: Generate QR code and auto-complete the step
//         if (paymentOption.paymentType === "Cash") {
//           try {
//             const qrCode = await generateQRCodeForPayment();

//             markStepComplete("Payment QR Generated", {
//               visibleTo: ["buyer", "seller"],
//               qrCodeUrl: qrCode,
//               paymentType: "Cash"
//             });

//             order.qrCodeData = qrCode;
//           } catch (qrError) {
//             return res.status(400).json({
//               success: false,
//               message: `QR Code generation failed: ${qrError.message}`,
//             });
//           }
//         }
//         // For Credit payments: Store credit details but DON'T auto-complete the step
//         else if (paymentOption.paymentType === "Credit") {
//           // Calculate due date
//           const dueDate = new Date();
//           dueDate.setDate(dueDate.getDate() + (paymentOption.creditPayment?.creditPeriodDays || 0));

//           const creditDetails = {
//             creditPeriodDays: paymentOption.creditPayment?.creditPeriodDays || 0,
//             interestRatePerYear: paymentOption.creditPayment?.interestRatePerYear || 0,
//             interestStartAfterDays: paymentOption.creditPayment?.interestStartAfterDays || 0,
//             paymentType: "Credit",
//             totalAmount: order.total,
//             dueDate: dueDate,
//             interestStartDate: new Date(dueDate.getTime() + (paymentOption.creditPayment?.interestStartAfterDays || 0) * 24 * 60 * 60 * 1000)
//           };

//           console.log("Creating Payment QR Generated step with creditDetails:", creditDetails); // Debug log

//           // Create the step but don't mark it as completed - SHARE CREDIT DETAILS
//           createStepIfNotExists("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             creditDetails: creditDetails,
//             qrCodeUrl: null, // No QR code for credit
//             paymentType: "Credit"
//           });

//           order.creditPaymentDetails = creditDetails;
//         }

//         break;

//       case "Payment QR Generated":
//         // For Credit payments, this step needs to be manually completed
//         if (actionBy !== "seller") {
//           return res.status(403).json({
//             success: false,
//             message: "Only seller can complete Payment QR Generated step",
//           });
//         }

//         // Check if this is a credit payment
//         const paymentOptionForQR = order.paymentOption;
//         if (paymentOptionForQR?.paymentType === "Credit") {
//           // Get existing credit details from the step or create new
//           const existingStep = order.processFlow.find(s => s.step === "Payment QR Generated");
//           let creditDetails = existingStep?.creditDetails;

//           if (!creditDetails) {
//             // If credit details don't exist, create them
//             const dueDate = new Date();
//             dueDate.setDate(dueDate.getDate() + (paymentOptionForQR.creditPayment?.creditPeriodDays || 0));

//             creditDetails = {
//               creditPeriodDays: paymentOptionForQR.creditPayment?.creditPeriodDays || 0,
//               interestRatePerYear: paymentOptionForQR.creditPayment?.interestRatePerYear || 0,
//               interestStartAfterDays: paymentOptionForQR.creditPayment?.interestStartAfterDays || 0,
//               paymentType: "Credit",
//               totalAmount: order.total,
//               dueDate: dueDate,
//               interestStartDate: new Date(dueDate.getTime() + (paymentOptionForQR.creditPayment?.interestStartAfterDays || 0) * 24 * 60 * 60 * 1000)
//             };
//           }

//           markStepComplete("Payment QR Generated", {
//             visibleTo: ["buyer", "seller"],
//             creditDetails: creditDetails, // ✅ CREDIT DETAILS SHARE KARO
//             paymentType: "Credit"
//           });
//         } else {
//           return res.status(400).json({
//             success: false,
//             message: "This step is only for manual completion in credit payments",
//           });
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

//         markStepComplete("Delivered", { visibleTo: ["buyer", "seller"] });
//         break;

//       default:
//         return res.status(400).json({ success: false, message: "Invalid step" });
//     }

//     // Save Order
//     await order.save();

//     res.status(200).json({
//       success: true,
//       message: `${step} marked as completed.`,
//       data: order,
//     });
//   } catch (err) {
//     console.error("Error in updateOrderProcessStep:", err);
//     res.status(500).json({
//       success: false,
//       message: "Server error",
//       error: err.message,
//     });
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

    // Helper function for marking step complete
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

    // Helper function for creating step without marking complete
    const createStepIfNotExists = (stepName, extraData = {}) => {
      let stepObj = order.processFlow.find((s) => s.step === stepName);
      if (!stepObj) {
        order.processFlow.push({
          step: stepName,
          completed: false,
          ...extraData,
        });
      } else {
        // Update existing step with new data
        Object.keys(extraData).forEach((key) => {
          stepObj[key] = extraData[key];
        });
      }
    };

    // INVOICE CREATION FUNCTION
    const createInvoiceOnEnquiry = async () => {
      // Check if invoice already exists
      const existing = await Invoice.findOne({ order: order._id });
      if (existing) {
        console.log("Invoice already exists. Skipping creation.");
        return;
      }

      if (!order.paymentOption)
        throw new Error("Payment Option not found for this order");

      const pay = order.paymentOption;

      let invoiceData = {
        order: order._id,
        buyer: order.buyer._id,
        seller: order.items[0]?.seller?._id,
        amount: order.total,
        status: "Pending",
        bankStatement: [],
      };

      // If Cash → Mark invoice paid
      if (pay.paymentType === "Cash") {
        invoiceData.status = "Paid";
        invoiceData.paidAt = new Date();

        // Add bank statement entry
        invoiceData.bankStatement.push({
          date: new Date(),
          description: "Cash Payment Received",
          debit: 0,
          credit: order.total,
          balance: 0,
        });
      } else if (pay.paymentType === "Credit") {
        // Add credit related values
        invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
        invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
        invoiceData.interestStartAfterDays =
          pay.creditPayment.interestStartAfterDays;

        // Due date = Today + creditPeriodDays
        const dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + pay.creditPayment.creditPeriodDays);
        invoiceData.dueDate = dueDate;

        // Interest accrual start date = dueDate + interestStartAfterDays
        const interestStart = new Date(dueDate);
        interestStart.setDate(
          interestStart.getDate() + pay.creditPayment.interestStartAfterDays
        );
        invoiceData.interestAccrualStartDate = interestStart;
      }

      // SAVE the invoice
      await Invoice.create(invoiceData);
    };

    // QR CODE GENERATION FUNCTION
    const generateQRCodeForPayment = async () => {
      const paymentOption = order.paymentOption;

      if (!paymentOption) {
        throw new Error("Payment option missing.");
      }

      const sellerBank = order.items[0]?.seller?.bankDetails;
      if (!sellerBank?.upiId) {
        throw new Error("Seller UPI ID not found.");
      }

      // Generate QR code only for Cash payments
      if (paymentOption.paymentType === "Cash") {
        const qrCode = await generateQRCode(sellerBank.upiId, order.total);
        return qrCode;
      }

      // For Credit payments, return null (no QR code)
      return null;
    };

    // ---------------------------------------------
    // MAIN STEP LOGIC
    // ---------------------------------------------
    switch (step) {
      case "Enquiry Received":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can send Enquiry Received",
          });

        markStepComplete("Enquiry Received", {
          visibleTo: ["buyer", "seller"],
        });

        // CREATE INVOICE IMMEDIATELY
        await createInvoiceOnEnquiry();

        break;

      case "Proforma Invoice":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can send Proforma Invoice",
          });

        markStepComplete("Proforma Invoice", {
          visibleTo: ["buyer", "seller"],
        });
        break;

      case "Proforma Accepted":
        if (actionBy !== "buyer")
          return res.status(403).json({
            success: false,
            message: "Only buyer can accept Proforma",
          });

        // UPDATE ORDER STATUS
        order.orderStatus = "Processing";

        markStepComplete("Proforma Accepted", {
          visibleTo: ["buyer", "seller"],
        });

        const paymentOption = order.paymentOption;

        if (!paymentOption) {
          return res.status(400).json({
            success: false,
            message: "Payment option missing.",
          });
        }

        // For Cash payments: Generate QR code and auto-complete the step
        if (paymentOption.paymentType === "Cash") {
          try {
            const qrCode = await generateQRCodeForPayment();

            markStepComplete("Payment QR Generated", {
              visibleTo: ["buyer", "seller"],
              qrCodeUrl: qrCode,
              paymentType: "Cash",
            });

            order.qrCodeData = qrCode;
          } catch (qrError) {
            return res.status(400).json({
              success: false,
              message: `QR Code generation failed: ${qrError.message}`,
            });
          }
        }
        // For Credit payments: Create step but DON'T mark complete - buyer will complete it
        else if (paymentOption.paymentType === "Credit") {
          // Calculate due date
          const dueDate = new Date();
          dueDate.setDate(
            dueDate.getDate() +
              (paymentOption.creditPayment?.creditPeriodDays || 0)
          );

          const creditDetails = {
            creditPeriodDays:
              paymentOption.creditPayment?.creditPeriodDays || 0,
            interestRatePerYear:
              paymentOption.creditPayment?.interestRatePerYear || 0,
            interestStartAfterDays:
              paymentOption.creditPayment?.interestStartAfterDays || 0,
            paymentType: "Credit",
            totalAmount: order.total,
            dueDate: dueDate,
            interestStartDate: new Date(
              dueDate.getTime() +
                (paymentOption.creditPayment?.interestStartAfterDays || 0) *
                  24 *
                  60 *
                  60 *
                  1000
            ),
          };

          // Create the step but don't mark it as completed - WAITING FOR BUYER TO COMPLETE
          createStepIfNotExists("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            creditDetails: creditDetails,
            qrCodeUrl: null, // No QR code for credit
            paymentType: "Credit",
          });

          order.creditPaymentDetails = creditDetails;
        }

        break;

      case "Payment QR Generated":
        // Determine current payment option
        const currentPaymentOption = order.paymentOption;

        if (!currentPaymentOption) {
          return res.status(400).json({
            success: false,
            message: "Payment option not found",
          });
        }

        if (currentPaymentOption.paymentType === "Credit") {
          // Credit payment: Buyer completes this step
          if (actionBy !== "buyer") {
            return res.status(403).json({
              success: false,
              message:
                "For credit payments, only buyer can complete Payment QR Generated step",
            });
          }

          // Get existing credit details from the step
          const existingStep = order.processFlow.find(
            (s) => s.step === "Payment QR Generated"
          );
          let creditDetails = existingStep?.creditDetails;

          if (!creditDetails) {
            // If credit details don't exist, create them
            const dueDate = new Date();
            dueDate.setDate(
              dueDate.getDate() +
                (currentPaymentOption.creditPayment?.creditPeriodDays || 0)
            );

            creditDetails = {
              creditPeriodDays:
                currentPaymentOption.creditPayment?.creditPeriodDays || 0,
              interestRatePerYear:
                currentPaymentOption.creditPayment?.interestRatePerYear || 0,
              interestStartAfterDays:
                currentPaymentOption.creditPayment?.interestStartAfterDays || 0,
              paymentType: "Credit",
              totalAmount: order.total,
              dueDate: dueDate,
              interestStartDate: new Date(
                dueDate.getTime() +
                  (currentPaymentOption.creditPayment?.interestStartAfterDays ||
                    0) *
                    24 *
                    60 *
                    60 *
                    1000
              ),
            };
          }

          markStepComplete("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            creditDetails: creditDetails,
            qrCodeUrl: null,
            paymentType: "Credit",
          });
        } else if (currentPaymentOption.paymentType === "Cash") {
          // Cash payment: Seller completes this step (if not already completed in Proforma Accepted)
          if (actionBy !== "seller") {
            return res.status(403).json({
              success: false,
              message:
                "For cash payments, only seller can complete Payment QR Generated step",
            });
          }

          // Check if QR code already exists
          const existingStep = order.processFlow.find(
            (s) => s.step === "Payment QR Generated"
          );
          if (!existingStep || !existingStep.completed) {
            try {
              const qrCode = await generateQRCodeForPayment();
              markStepComplete("Payment QR Generated", {
                visibleTo: ["buyer", "seller"],
                qrCodeUrl: qrCode,
                paymentType: "Cash",
              });
              order.qrCodeData = qrCode;
            } catch (qrError) {
              return res.status(400).json({
                success: false,
                message: `QR Code generation failed: ${qrError.message}`,
              });
            }
          }
        } else {
          return res.status(400).json({
            success: false,
            message: "Invalid payment type",
          });
        }
        break;

      case "Payment Received":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can confirm payment",
          });

        markStepComplete("Payment Received", {
          visibleTo: ["buyer", "seller"],
        });
        break;

      case "Invoice Uploaded":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can upload invoice",
          });

        const itemSummary = order.items.map((i) => i.productName).join(", ");
        const totalItems = order.items.length;
        const totalAmount = order.total;

        markStepComplete("Invoice Uploaded", {
          visibleTo: ["buyer", "seller"],
          invoiceSummary: { itemSummary, totalItems, totalAmount },
        });
        break;

      case "Dispatch":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can dispatch order",
          });

        markStepComplete("Dispatch", { visibleTo: ["buyer", "seller"] });
        break;

      case "Delivered":
        if (actionBy !== "seller")
          return res.status(403).json({
            success: false,
            message: "Only seller can mark as delivered",
          });

           // UPDATE ORDER STATUS
        order.orderStatus = "Completed";

        markStepComplete("Delivered", { visibleTo: ["buyer", "seller"] });
        break;

      default:
        return res
          .status(400)
          .json({ success: false, message: "Invalid step" });
    }

    // Save Order
    await order.save();

    res.status(200).json({
      success: true,
      message: `${step} marked as completed.`,
      data: order,
    });
  } catch (err) {
    console.error("Error in updateOrderProcessStep:", err);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message,
    });
  }
};

export const updateOrderItem = async (req, res, next) => {
  try {
    const { orderId, itemId, quantity } = req.body;

    if (!orderId || !itemId || !quantity) {
      return res.status(400).json({
        success: false,
        message: "orderId, itemId and quantity are required",
      });
    }

    const order = await Order.findById(orderId);
    if (!order) {
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });
    }

    const item = order.items.find((it) => it._id.toString() === itemId);
    if (!item) {
      return res
        .status(404)
        .json({ success: false, message: "Item not found" });
    }

    // Restore unit price (each item cost)
    const unitPrice = item.finalPrice / item.quantity;

    // Restore unit discount (discount of only 1 unit)
    const unitDiscount = order.discountFromPayment / item.quantity;

    // Update quantity
    item.quantity = quantity;

    // Recalculate prices using unit price
    const newFinalPrice = unitPrice * quantity;
    item.finalPrice = newFinalPrice;

    order.subTotal = newFinalPrice;

    // update discount
    const newDiscount = unitDiscount * quantity;
    order.discountFromPayment = newDiscount;

    order.total = newFinalPrice - newDiscount;

    await order.save();

    return res.status(200).json({
      success: true,
      message: "Order item updated successfully",
      order,
    });
  } catch (error) {
    console.error("Error updating order:", error);
    next(error);
  }
};
