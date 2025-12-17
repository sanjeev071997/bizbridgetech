import mongoose from "mongoose";
import Invoice from "../models/invoiceModel.js";
import Order from "../models/orderModel.js";
import PaymentOption from "../models/paymentOption.js";
import { startOfDay, daysBetween } from "../utils/InvoiceTime.js";
import Errorhandler from '../utils/Errorhandler.js';

// Create Invoice from Order
export const createInvoice = async (req, res) => {
  const { orderId } = req.body;

  const order = await Order.findById(orderId).populate("paymentOption");
  if (!order) return res.status(404).json({ success:false, message:"Order not found" });

  const po = order.paymentOption; 
  let creditPeriodDays = 0, interestRatePerYear = 0, interestStartAfterDays = 0;

  if (po?.paymentType === "Credit" || po?.paymentType === "Both") {
    creditPeriodDays       = po.creditPayment?.creditPeriodDays ?? 0;
    interestRatePerYear    = po.creditPayment?.interestRatePerYear ?? 0;
    interestStartAfterDays = po.creditPayment?.interestStartAfterDays ?? 0;
  }

  const invoiceDate = new Date(); 
  const dueDate = creditPeriodDays > 0
    ? new Date(invoiceDate.getTime() + creditPeriodDays * 86400000)
    : null;

  const interestAccrualStartDate = (dueDate && interestStartAfterDays > 0)
    ? new Date(dueDate.getTime() + interestStartAfterDays * 86400000)
    : (dueDate || null);

  const seller = order.items?.[0]?.seller || undefined;

  // Initial bank statement (debit = invoice total)
  const firstEntry = {
    date: invoiceDate,
    description: "Invoice Created",
    debit: order.total,
    credit: 0,
    balance: order.total,
  };

  const invoice = await Invoice.create({
    order: order._id,
    buyer: order.buyer,
    seller,
    amount: order.total,
    creditPeriodDays,
    interestRatePerYear,
    interestStartAfterDays,
    dueDate,
    interestAccrualStartDate,
    status: "Pending",
    lastInterestAppliedOn: null,
    bankStatement: [firstEntry],
  });

  res.status(201).json({ success:true, message:"Invoice created", data: invoice });
};

export const recordPayment = async (req, res, next) => {
  const { id } = req.params;                 
  const { amount, paidAt, note } = req.body; 

  if (!amount || amount <= 0) {
    return res.status(400).json({ success: false, message: "Amount must be > 0" });
  }

  const invoice = await Invoice.findById(id);
  if (!invoice) {
    return res.status(404).json({ success: false, message: "Invoice not found" });
  }

  const lastBalance = invoice.bankStatement.at(-1)?.balance ?? invoice.amount;

  // Default to today's date if not provided
  let tDate = paidAt ? new Date(paidAt) : new Date();

  // Validate
  if (isNaN(tDate.getTime())) {
    tDate = new Date(); 
  }

  const newBalance = Math.max(+(lastBalance - amount).toFixed(2), 0);

  invoice.bankStatement.push({
    date: tDate,
    description: note || "Payment received",
    debit: 0,
    credit: amount,
    balance: newBalance,
  });

  if (newBalance <= 0) {
    invoice.status = "Paid";
    invoice.paidAt = tDate;
  } else if (invoice.dueDate && new Date() > invoice.dueDate) {
    invoice.status = "Overdue";
  } else {
    invoice.status = "Pending";
  }

  await invoice.save();

  res.json({
    success: true,
    message: "Payment recorded",
    data: invoice,
  });
};

//  Get Invoice + latest balance
export const getInvoice = async (req, res) => {
  const invoice = await Invoice.findById(req.params.id)
    .populate("order")
    .populate("buyer")
    .populate("seller");
  if (!invoice) return res.status(404).json({ success:false, message:"Not found" });

  const latestBalance = invoice.bankStatement.at(-1)?.balance ?? 0;
  res.json({ success:true, data: { invoice, latestBalance } });
};

//  Full bank statement for an invoice
export const getInvoiceStatement = async (req, res) => {
  const invoice = await Invoice.findById(req.params.id, { bankStatement: 1 });
  if (!invoice) return res.status(404).json({ success:false, message:"Not found" });
  res.json({ success:true, count: invoice.bankStatement.length, data: invoice.bankStatement });
};

/**
 * DAILY INTEREST: add exactly 1 day's interest when eligible.
 * - Interest starts AFTER (dueDate + interestStartAfterDays).
 * - Applies once per calendar day (IST), tracked via lastInterestAppliedOn.
 * - Interest is computed on the latest outstanding balance (compounding effect).
 */
export const applyDailyInterestIfNeeded = async (invoice, runAt = new Date()) => {
  if (invoice.status === "Paid") return;

  const today = startOfDay(runAt);

  // must have an accrual start date AND today >= accrual start
  if (!invoice.interestAccrualStartDate) return;
  if (today < startOfDay(invoice.interestAccrualStartDate)) return;

  // already applied for today?
  if (invoice.lastInterestAppliedOn && startOfDay(invoice.lastInterestAppliedOn).getTime() === today.getTime()) {
    return;
  }

  // ensure we only apply for "next" day after last applied
  let lastApplied = invoice.lastInterestAppliedOn
    ? startOfDay(invoice.lastInterestAppliedOn)
    : startOfDay(new Date(invoice.interestAccrualStartDate));

  // if we are behind multiple days, we will catch up 1 day at a time across cron runs.
  // For strict once-per-day, just apply for TODAY if at least 1 day has passed since lastApplied.
  const daysGap = daysBetween(lastApplied, today);
  if (daysGap <= 0) return; // nothing to do

  const lastBalance = invoice.bankStatement.at(-1)?.balance ?? invoice.amount;
  if (lastBalance <= 0) {
    // nothing outstanding => mark pending/paid accordingly
    invoice.status = invoice.status === "Paid" ? "Paid" : "Pending";
    invoice.lastInterestAppliedOn = today;
    await invoice.save();
    return;
  }

  const dailyRate = (invoice.interestRatePerYear || 0) / 100 / 365; 
  const interest = +(lastBalance * dailyRate).toFixed(2);
  if (interest <= 0) {
    invoice.lastInterestAppliedOn = today;
    await invoice.save();
    return;
  }

  const newBalance = +(lastBalance + interest).toFixed(2);

  invoice.bankStatement.push({
    date: today,
    description: "Daily interest (overdue)",
    debit: interest,
    credit: 0,
    balance: newBalance,
  });

  invoice.status = "Overdue";
  invoice.lastInterestAppliedOn = today;

  await invoice.save();
};

//  Cron runner: apply daily interest to all eligible invoices
export const runDailyInterestForAll = async (runAt = new Date()) => {
  const invoices = await Invoice.find({
    status: { $ne: "Paid" },
    interestAccrualStartDate: { $ne: null }
  });

  for (const inv of invoices) {
    await applyDailyInterestIfNeeded(inv, runAt);
  }
};

//  Manual trigger API (use admin auth in real app) 
export const runInterestCronNow = async (req, res) => {
  await runDailyInterestForAll(new Date());
  res.json({ success:true, message:"Daily interest run executed" });
};

export const sellerInvoice = async (req, res) => {
  try {
    const { order, seller, buyer } = req.body;

    // Validation: orderId required + seller OR buyer required
    if (!order || (!seller && !buyer)) {
      return res.status(400).json({
        success: false,
        message: "orderId and either seller or buyer is required",
      });
    }

    // Build dynamic query
    const query = { order: order };
    if (seller) query.seller = seller;
    if (buyer) query.buyer = buyer;

    // Fetch invoice
    const invoice = await Invoice.findOne(query).populate("order").populate("buyer").populate("seller");

    if (!invoice) {
      return res.status(404).json({
        success: false,
        message: "Invoice not found",
      });
    }

    // Calculate last balance
    const latestBalance = invoice.bankStatement.at(-1)?.balance ?? 0;

    return res.status(200).json({
      success: true,
      message: "Invoice fetched successfully",
      data: {
        invoice,
        latestBalance,
      },
    });

  } catch (error) {
    console.error("sellerInvoice error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};

// // Get Seller Invoice
// export const getSellerAllInvoices = async (req, res) => {
//   try {
//     const { id } = req.params;
//      if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({
//         success: false,
//         message: "Invalid invoice ID",
//       });
//     }
//     // Fetch all invoices of this seller
//     const invoices = await Invoice.find({ seller: id })
//       .populate("order", "total")
//       .populate("buyer", "name phone mode")
//       .populate("seller", "name phone mode")
//       .sort({ createdAt: -1 });

//     if (!invoices.length) {
//       return res.status(404).json({
//         success: false,
//         message: "No invoices found for this seller",
//       });
//     }

//     // Optional: add latest balance per invoice
//     const invoicesWithBalance = invoices.map((invoice) => {
//       const latestBalance =
//         invoice.bankStatement?.at(-1)?.balance ?? 0;

//       return {
//         ...invoice.toObject(),
//         latestBalance,
//       };
//     });

//     return res.status(200).json({
//       success: true,
//       message: "Seller invoices fetched successfully",
//       totalInvoices: invoices.length,
//       data: invoicesWithBalance,
//     });
//   } catch (error) {
//     console.error("getSellerAllInvoices error:", error);
//     return res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// };


// // Get Seller Invoice (with Pagination)
// export const getSellerAllInvoices = async (req, res) => {
//   try {
//     const { id } = req.params;

//     // Pagination params
//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;
//     const skip = (page - 1) * limit;

//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({
//         success: false,
//         message: "Invalid seller ID",
//       });
//     }

//     // Total count (for pagination)
//     const totalInvoices = await Invoice.countDocuments({ seller: id });

//     // if (!totalInvoices) {
//     //   return res.status(404).json({
//     //     success: false,
//     //     message: "No invoices found for this seller",
//     //   });
//     // }

//     if (totalInvoices === 0) {
//   return res.status(200).json({
//     success: true,
//     message: "No invoices found for this seller",
//     pagination: {
//       totalInvoices: 0,
//       currentPage: page,
//       limit,
//       totalPages: 0,
//     },
//     data: [],
//   });
// }


//     // Fetch paginated invoices
//     const invoices = await Invoice.find({ seller: id })
//       .populate("order", "total")
//       .populate("buyer", "name phone mode")
//       .populate("seller", "name phone mode")
//       .sort({ createdAt: -1 })
//       .skip(skip)
//       .limit(limit);

//     // Add latest balance (bank statement closing balance)
//     const invoicesWithBalance = invoices.map((invoice) => {
//       const latestBalance =
//         invoice.bankStatement?.length > 0
//           ? invoice.bankStatement[invoice.bankStatement.length - 1].balance
//           : invoice.amount;

//       return {
//         ...invoice.toObject(),
//         latestBalance,
//       };
//     });

//     return res.status(200).json({
//       success: true,
//       message: "Seller invoices fetched successfully",
//       pagination: {
//         totalInvoices,
//         currentPage: page,
//         limit,
//         totalPages: Math.ceil(totalInvoices / limit),
//       },
//       data: invoicesWithBalance,
//     });
//   } catch (error) {
//     console.error("getSellerAllInvoices error:", error);
//     return res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// };

export const getSellerAllInvoices = async (req, res) => {
  try {
    const { id } = req.params;

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid seller ID",
      });
    }

    const totalInvoices = await Invoice.countDocuments({ seller: id });

    // Important: DO NOT send 404
    const invoices = await Invoice.find({ seller: id })
      .populate("order", "total")
      .populate("buyer", "name phone mode")
      .populate("seller", "name phone mode")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const invoicesWithBalance = invoices.map((invoice) => ({
      ...invoice.toObject(),
      latestBalance:
        invoice.bankStatement?.at(-1)?.balance ?? invoice.amount,
    }));

    return res.status(200).json({
      success: true,
      message:
        totalInvoices === 0
          ? "No invoices found for this seller"
          : "Seller invoices fetched successfully",
      pagination: {
        totalInvoices,
        currentPage: page,
        limit,
        totalPages: Math.ceil(totalInvoices / limit),
      },
      data: invoicesWithBalance,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};


