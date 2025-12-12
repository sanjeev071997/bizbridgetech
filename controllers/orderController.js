import mongoose from "mongoose";
import Order from "../models/orderModel.js";
import Cart from "../models/cartModel.js";
import Invoice from "../models/invoiceModel.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import ErrorHandler from "../utils/Errorhandler.js";
import { generateQRCode } from "../utils/generateQRCode.js";

// Create Order
export const createOrder = async (req, res) => {
  try {
    const { seller, selectPaymentType } = req.body;

    console.log("selectPaymentType",  selectPaymentType, seller);

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
    const orderItems = cart.items.map((i) => {
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
        gstAmount: gstAmount,
        finalPrice: finalPrice,
        subTotal: subTotal,
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

    // Order level totals
    const discount = Number(cart.discountFromPayment || 0);
    const orderTotal = orderSubTotal - discount;
    const newOrder = await Order.create({
      buyer: cart.user._id,
      items: orderItems,
      subTotal: orderSubTotal,
      discountFromPayment: discount,
      total: orderTotal,
      paymentOption: cart.paymentOption?._id,
      processFlow: defaultSteps,
      selectPaymentType
    });

    // Fetch clean populated order
    const order = await Order.findById(newOrder._id)
      .populate("buyer", "name mode")
      .populate({
        path: "items.seller",
        select: "name mode",
      });

    // Remove cart
    await Cart.findByIdAndDelete(cart._id);

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      order,
    });
  } catch (error) {
    // console.error("createOrder error:", error);
    // res.status(500).json({
    //   success: false,
    //   message: "Server Error",
    // });
     return next(new ErrorHandler(error.message, 500))
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
            category: item.category,
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
  const sellerId = req.user._id; 

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

    // INVOICE CREATION WITH FINAL PAYMENT TYPE
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

      // CREDIT → CREDIT TERMS
      if (finalPaymentType === "Credit") {
        const pay = order.paymentOption;

        invoiceData.creditPeriodDays = pay.creditPayment.creditPeriodDays;
        invoiceData.interestRatePerYear = pay.creditPayment.interestRatePerYear;
        invoiceData.interestStartAfterDays =
          pay.creditPayment.interestStartAfterDays;

        const dueDate = new Date();
        dueDate.setDate(
          dueDate.getDate() + pay.creditPayment.creditPeriodDays
        );
        invoiceData.dueDate = dueDate;

        const interestStart = new Date(dueDate);
        interestStart.setDate(
          interestStart.getDate() + pay.creditPayment.interestStartAfterDays
        );
        invoiceData.interestAccrualStartDate = interestStart;
      }

      await Invoice.create(invoiceData);
    };

    // QR FOR FINAL PAYMENT TYPE
    const generateQRCodeForPayment = async () => {
      const sellerBank = order.items[0]?.seller?.bankDetails;

      if (!sellerBank?.upiId)
        throw new Error("Seller UPI ID not found.");

      if (finalPaymentType === "Cash") {
        return await generateQRCode(sellerBank.upiId, order.total);
      }

      return null; // no QR for Credit
    };

    // MAIN LOGIC
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

        order.orderStatus = "Processing";

        markStepComplete("Proforma Accepted", {
          visibleTo: ["buyer", "seller"],
        });

        // Payment type wise logic
        if (finalPaymentType === "Cash") {
          const qrCode = await generateQRCodeForPayment();

          markStepComplete("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            qrCodeUrl: qrCode,
            paymentType: "Cash",
          });

          order.qrCodeData = qrCode;
        }

        if (finalPaymentType === "Credit") {
          const pay = order.paymentOption;

          const dueDate = new Date();
          dueDate.setDate(
            dueDate.getDate() +
              (pay.creditPayment?.creditPeriodDays || 0)
          );

          const creditDetails = {
            paymentType: "Credit",
            totalAmount: order.total,
            creditPeriodDays: pay.creditPayment.creditPeriodDays,
            interestRatePerYear: pay.creditPayment.interestRatePerYear,
            interestStartAfterDays:
              pay.creditPayment.interestStartAfterDays,
            dueDate,
            interestStartDate: new Date(
              dueDate.getTime() +
                (pay.creditPayment.interestStartAfterDays || 0) *
                  86400000
            ),
          };

          createStepIfNotExists("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            creditDetails,
            qrCodeUrl: null,
            paymentType: "Credit",
          });

          order.creditPaymentDetails = creditDetails;
        }
        break;

      case "Payment QR Generated":
        if (finalPaymentType === "Credit") {
          if (actionBy !== "buyer")
            return res.status(403).json({
              success: false,
              message:
                "For credit payments, only buyer can complete this step",
            });

          const existingStep = order.processFlow.find(
            (s) => s.step === "Payment QR Generated"
          );

          markStepComplete("Payment QR Generated", {
            ...existingStep,
            visibleTo: ["buyer", "seller"],
            paymentType: "Credit",
            qrCodeUrl: null,
          });
        }

        if (finalPaymentType === "Cash") {
          if (actionBy !== "seller")
            return res.status(403).json({
              success: false,
              message:
                "For cash payments, only seller can complete this step",
            });

          const qr = await generateQRCodeForPayment();

          markStepComplete("Payment QR Generated", {
            visibleTo: ["buyer", "seller"],
            qrCodeUrl: qr,
            paymentType: "Cash",
          });

          order.qrCodeData = qr;
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
          paymentType: finalPaymentType,
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

        order.orderStatus = "Completed";

        markStepComplete("Delivered", {
          visibleTo: ["buyer", "seller"],
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
    return next(new ErrorHandler(err.message, 500))
  }
};

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

      const perUnitFinal =
        (item.discountPrice || 0) + (item.gstAmount || 0);

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
    order.total = Number((order.subTotal - order.discountFromPayment).toFixed(2));

    await order.save();

    return res.status(200).json({
      success: true,
      message: "Order items updated successfully",
      order,
    });
  } catch (error) {
    return next(new ErrorHandler(error.message, 500))
  }
};


