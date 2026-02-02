import mongoose from "mongoose";
import Invoice from "../models/invoiceModel.js";
import Order from "../models/orderModel.js";
import PaymentOption from "../models/paymentOption.js";
import {
  startOfDay,
  getMonthEndDate,
  daysBetween,
  isLastDayOfMonth,
  addDays,
  differenceInCalendarDays,
  endOfDay,
  getDaysInYear,
} from "../utils/InvoiceTime.js";
import Errorhandler from "../utils/Errorhandler.js";

const roundToTwo = (num) => {
  return Math.round((num + Number.EPSILON) * 100) / 100;
};

// Create Invoice from Order
export const createInvoice = async (req, res) => {
  const { orderId } = req.body;

  const order = await Order.findById(orderId).populate("paymentOption");
  if (!order)
    return res.status(404).json({ success: false, message: "Order not found" });

  const po = order.paymentOption;
  let creditPeriodDays = 0,
    interestRatePerYear = 0,
    interestStartAfterDays = 0;

  if (po?.paymentType === "Credit" || po?.paymentType === "Both") {
    creditPeriodDays = po.creditPayment?.creditPeriodDays ?? 0;
    interestRatePerYear = po.creditPayment?.interestRatePerYear ?? 0;
    interestStartAfterDays = po.creditPayment?.interestStartAfterDays ?? 0;
  }

  const invoiceDate = new Date();

  // Calculate dueDate (invoiceDate + creditPeriodDays)
  const dueDate =
    creditPeriodDays > 0
      ? new Date(invoiceDate.getTime() + creditPeriodDays * 86400000)
      : null;

  // CORRECTION: interestAccrualStartDate = dueDate (not dueDate + interestStartAfterDays)
  // Because interest starts immediately after due date
  const interestAccrualStartDate = dueDate ? new Date(dueDate) : null;

  const seller = order.items?.[0]?.seller || undefined;
  const invoiceAmount = roundToTwo(order.total);

  const paymentStatus = po?.paymentType === "Cash" ? "Approved" : "Pending";

  // Initial bank statement (debit = invoice total)
  const firstEntry = {
    date: invoiceDate,
    description: "Invoice Created",
    debit: invoiceAmount,
    credit: 0,
    balance: invoiceAmount,
    paymentStatus,
    // paymentStatus: "Approved"
  };

  const invoice = await Invoice.create({
    order: order._id,
    buyer: order.buyer,
    seller,
    amount: invoiceAmount,
    creditPeriodDays,
    interestRatePerYear,
    interestStartAfterDays: interestStartAfterDays,
    dueDate,
    interestAccrualStartDate,
    status: "Pending",
    lastInterestAppliedOn: null,
    lastMonthEndInterestApplied: null,
    nextInterestApplicationDate: getNextMonthEndDate(dueDate),
    bankStatement: [firstEntry],
  });

  res
    .status(201)
    .json({ success: true, message: "Invoice created", data: invoice });
};

// Helper: Get next month-end date after a given date
const getNextMonthEndDate = (date) => {
  if (!date) return null;

  const d = new Date(date);
  const currentMonthEnd = getMonthEndDate(d);

  // If date is already past current month-end, get next month's end
  if (d > currentMonthEnd) {
    const nextMonth = new Date(d);
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    return getMonthEndDate(nextMonth);
  }

  return currentMonthEnd;
};

// Get Invoice + latest balance
export const recordPayment = async (req, res, next) => {
  const { id } = req.params;
  let { amount, paidAt, note } = req.body;

  // Convert & validate amount
  amount = Number(amount);

  if (!amount || amount <= 0) {
    return res
      .status(400)
      .json({ success: false, message: "Amount must be > 0" });
  }

  const invoice = await Invoice.findById(id);
  if (!invoice) {
    return res
      .status(404)
      .json({ success: false, message: "Invoice not found" });
  }

  // IMPORTANT CHECK
  const hasPendingApproval = invoice.bankStatement.some(
    (entry) => entry.paymentStatus === "Pending"
  );

  if (hasPendingApproval) {
    return res.status(400).json({
      success: false,
      message:
        "Previous payment is pending seller approval. You cannot add a new payment.",
    });
  }

  // Last balance
  const lastBalance = invoice.bankStatement.at(-1)?.balance ?? invoice.amount;

  // Amount should not exceed pending balance
  if (amount > lastBalance) {
    return res.status(400).json({
      success: false,
      message: `Payment amount cannot exceed pending balance (${lastBalance})`,
    });
  }

  // paidAt fallback → current date
  let tDate = paidAt ? new Date(paidAt) : new Date();
  if (isNaN(tDate.getTime())) {
    tDate = new Date();
  }

  // Round values to 2 decimals
  const paidAmount = Math.round((amount + Number.EPSILON) * 100) / 100;
  const newBalance =
    Math.round((lastBalance - paidAmount + Number.EPSILON) * 100) / 100;

  invoice.bankStatement.push({
    date: tDate,
    description: note || "Payment received",
    debit: 0,
    credit: paidAmount,
    balance: newBalance,
    paymentStatus: "Pending", // seller approval required
  });

  // Update invoice status
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
    message: "Payment recorded successfully and waiting for seller approval",
    data: invoice,
  });
};

// Get Invoice
export const getInvoice = async (req, res) => {
  const invoice = await Invoice.findById(req.params.id)
    .populate("order")
    .populate("buyer")
    .populate("seller");
  if (!invoice)
    return res.status(404).json({ success: false, message: "Not found" });

  const latestBalance = invoice.bankStatement.at(-1)?.balance ?? 0;

  // Calculate next interest application date
  let nextInterestDate = invoice.nextInterestApplicationDate;
  if (!nextInterestDate && invoice.dueDate) {
    nextInterestDate = getNextMonthEndDate(invoice.dueDate);
  }

  res.json({
    success: true,
    data: {
      invoice,
      latestBalance,
      nextInterestApplicationDate: nextInterestDate,
    },
  });
};

// Full bank statement for an invoice
export const getInvoiceStatement = async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid invoice id",
      });
    }

    const invoice = await Invoice.aggregate([
      {
        $match: {
          _id: new mongoose.Types.ObjectId(id),
        },
      },
      {
        $project: {
          _id: 0,
          bankStatement: {
            $filter: {
              input: "$bankStatement",
              as: "item",
              cond: {
                $and: [
                  { $gt: ["$$item.credit", 0] },
                  { $eq: ["$$item.paymentStatus", "Pending"] },
                ],
              },
            },
          },
        },
      },
    ]);

    if (!invoice.length) {
      return res.status(404).json({
        success: false,
        message: "Invoice not found or no pending credit entries",
      });
    }

    res.status(200).json({
      success: true,
      count: invoice[0].bankStatement.length,
      data: invoice[0].bankStatement,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// BALANCE HELPER (Interest entries bittu balance nodalu)
// const getBalanceOnDate = (invoice, date) => {
//   const targetDate = startOfDay(new Date(date));
//   let balance = invoice.amount;

//   const sortedStatements = [...invoice.bankStatement]
//     .filter((entry) => !entry.description.toLowerCase().includes("interest"))
//     .sort((a, b) => new Date(a.date) - new Date(b.date));

//   for (const entry of sortedStatements) {
//     if (startOfDay(new Date(entry.date)) <= targetDate) {
//       balance = entry.balance;
//     } else {
//       break;
//     }
//   }
//   return balance;
// };

// DAILY INTEREST HELPER (Leap Year Optimized)
// const calculateDailyInterestForPeriod = (invoice, startDate, endDate) => {
//   const ratePerYear = (invoice.interestRatePerYear || 0) / 100;

//   const payments = [...invoice.bankStatement]
//     .filter((txn) => !txn.description.toLowerCase().includes("interest"))
//     .sort((a, b) => new Date(a.date) - new Date(b.date));

//   let totalInterest = 0;
//   let periodStart = startOfDay(new Date(startDate));
//   const finalEnd = startOfDay(new Date(endDate));
//   let currentBalance = getBalanceOnDate(invoice, startDate);

//   for (const txn of payments) {
//     const txnDate = startOfDay(new Date(txn.date));

//     if (txnDate > periodStart && txnDate <= finalEnd) {
//       const days = differenceInCalendarDays(txnDate, periodStart);
//       if (days > 0) {
//         // Dynamic daily rate based on year (365 or 366)
//         const dailyRate = ratePerYear / getDaysInYear(periodStart);
//         totalInterest += currentBalance * dailyRate * days;
//       }
//       currentBalance = txn.balance;
//       periodStart = txnDate;
//     }
//   }

//   // Last payment ninda end date varege
//   const remainingDays = differenceInCalendarDays(finalEnd, periodStart) + 1;
//   if (remainingDays > 0) {
//     const dailyRate = ratePerYear / getDaysInYear(periodStart);
//     totalInterest += currentBalance * dailyRate * remainingDays;
//   }

//   return +totalInterest.toFixed(2);
// };

// APPLY MONTHLY INTEREST
// export const applyMonthlyInterestIfNeeded = async (
//   invoice,
//   runAt = new Date()
// ) => {
//   if (invoice.status === "Paid") return;

//   const today = startOfDay(runAt);
//   if (!isLastDayOfMonth(today)) return;
//   if (!invoice.dueDate || !invoice.interestRatePerYear) return;

//   const dueDate = startOfDay(new Date(invoice.dueDate));
//   if (today < dueDate) return;

//   const monthName = today.toLocaleString("default", {
//     month: "long",
//     year: "numeric",
//   });
//   const interestDesc = `Monthly interest for ${monthName}`;

//   const alreadyApplied = invoice.bankStatement.some(
//     (txn) => txn.description === interestDesc
//   );
//   if (alreadyApplied) return;

//   const interest = calculateDailyInterestForPeriod(invoice, dueDate, today);
//   if (interest <= 0) return;

//   const lastBalance = invoice.bankStatement.at(-1)?.balance ?? invoice.amount;
//   const newBalance = +(lastBalance + interest).toFixed(2);

//   invoice.bankStatement.push({
//     date: endOfDay(today),
//     description: interestDesc,
//     debit: interest,
//     credit: 0,
//     balance: newBalance,
//     paymentStatus: "Approved",
//   });

//   invoice.status = "Overdue";
//   invoice.lastMonthEndInterestApplied = endOfDay(today);
//   invoice.markModified("bankStatement");
//   await invoice.save();
// };

// CALCULATE INTEREST TILL DATE (API Response)
export const calculateInterestTillDate = async (req, res) => {
  try {
    const { id } = req.params;
    const { tillDate } = req.body;

    const invoice = await Invoice.findById(id);
    if (!invoice)
      return res
        .status(404)
        .json({ success: false, message: "Invoice not found" });

    const endDate = startOfDay(tillDate ? new Date(tillDate) : new Date());
    const dueDate = startOfDay(new Date(invoice.dueDate));

    if (endDate < dueDate) {
      return res.json({
        success: true,
        data: { totalInterest: 0, currentOutstanding: invoice.amount },
      });
    }

    const totalInterest = calculateDailyInterestForPeriod(
      invoice,
      dueDate,
      endDate
    );
    const currentBalance =
      invoice.bankStatement.at(-1)?.balance ?? invoice.amount;

    res.json({
      success: true,
      data: {
        totalInterest,
        currentOutstanding: +(currentBalance + totalInterest).toFixed(2),
        daysInYearUsed: getDaysInYear(endDate), // Debugging gagi
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// Cron runner: apply monthly interest to all eligible invoices
// export const runMonthlyInterestForAll = async (runAt = new Date()) => {
//   // Only run on month-end dates
//   if (!isLastDayOfMonth(runAt)) {
//     console.log(`Not a month-end date: ${runAt.toISOString()}`);
//     return;
//   }

//   // Find invoices that:
//   // 1. Are not paid
//   // 2. Have dueDate passed
//   // 3. Either have nextInterestApplicationDate = today OR no interest applied yet
//   const today = startOfDay(runAt);

//   const invoices = await Invoice.find({
//     status: { $ne: "Paid" },
//     dueDate: { $lte: today },
//     $or: [
//       { nextInterestApplicationDate: { $lte: today } },
//       { nextInterestApplicationDate: null, lastMonthEndInterestApplied: null },
//     ],
//   });

//   console.log(
//     `Running monthly interest for ${
//       invoices.length
//     } invoices on ${runAt.toISOString()}`
//   );

//   for (const inv of invoices) {
//     await applyMonthlyInterestIfNeeded(inv, runAt);
//   }

//   console.log(`Monthly interest application completed`);
// };

// Manual trigger API
export const runInterestCronNow = async (req, res) => {
  await runMonthlyInterestForAll(new Date());
  res.json({ success: true, message: "Monthly interest run executed" });
};

// Get invoice by order, seller, or buyer
export const sellerInvoice = async (req, res) => {
  try {
    const { order, seller, buyer } = req.body;

    if (!order || (!seller && !buyer)) {
      return res.status(400).json({
        success: false,
        message: "orderId and either seller or buyer is required",
      });
    }

    const query = { order: order };
    if (seller) query.seller = seller;
    if (buyer) query.buyer = buyer;

    const invoice = await Invoice.findOne(query)
      .populate("order")
      .populate("buyer")
      .populate("seller");

    if (!invoice) {
      return res.status(404).json({
        success: false,
        message: "Invoice not found",
      });
    }

    // const latestBalance = invoice.bankStatement.at(-1)?.balance ?? 0;
    // Get last Approved bankStatement entry
    const approvedStatements =
      invoice.bankStatement?.filter(
        (entry) => entry.paymentStatus === "Approved"
      ) || [];

    const latestBalance =
      approvedStatements.length > 0 ? approvedStatements.at(-1).balance : 0;

    return res.status(200).json({
      success: true,
      message: "Invoice fetched successfully",
      data: {
        invoice,
        latestBalance,
        nextInterestApplicationDate:
          invoice.nextInterestApplicationDate ||
          getNextMonthEndDate(invoice.dueDate),
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

// Get Seller Invoice (with Pagination)
export const getSellerAllInvoices = async (req, res) => {
  try {
    const { id } = req.params;

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { status } = req.query;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid seller ID",
      });
    }

    const query = { seller: id };

    if (status) {
      if (status === "All") {
        // no filter
      } else if (Array.isArray(status)) {
        query.status = { $in: status };
      } else {
        query.status = status;
      }
    } else {
      query.status = { $in: ["Pending", "Overdue", "Paid"] };
    }

    const totalInvoices = await Invoice.countDocuments(query);

    const invoices = await Invoice.find(query)
      .populate("order", "items total")
      .populate("buyer", "name phone mode")
      .populate("seller", "name phone mode")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const invoicesWithBalance = invoices.map((invoice) => {
      // Only approved statements
      const approvedStatements =
        invoice.bankStatement?.filter(
          (item) => item.paymentStatus === "Approved"
        ) || [];

      // Latest balance should come from last APPROVED entry only
      const latestBalance =
        approvedStatements.length > 0
          ? approvedStatements.at(-1).balance
          : invoice.amount;

      const nextInterestDate =
        invoice.nextInterestApplicationDate ||
        getNextMonthEndDate(invoice.dueDate);

      return {
        ...invoice.toObject(),
        bankStatement: approvedStatements,
        latestBalance,
        nextInterestApplicationDate: nextInterestDate,
      };
    });

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
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Get Buyer Invoice (with Pagination)
export const getBuyerAllInvoices = async (req, res) => {
  try {
    const { id } = req.params;

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const { status } = req.query;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid buyer ID",
      });
    }

    const query = { buyer: id };

    if (status) {
      if (status === "All") {
        // no filter
      } else if (Array.isArray(status)) {
        query.status = { $in: status };
      } else {
        query.status = status;
      }
    } else {
      query.status = { $in: ["Pending", "Overdue", "Paid"] }; // "Paid" included for buyers
    }

    const totalInvoices = await Invoice.countDocuments(query);

    const invoices = await Invoice.find(query)
      .populate("order", "items total")
      .populate("buyer", "name phone mode")
      .populate("seller", "name phone mode bankDetails")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const invoicesWithBalance = invoices.map((invoice) => {
      // Only approved statements
      const approvedStatements =
        invoice.bankStatement?.filter(
          (item) => item.paymentStatus === "Approved"
        ) || [];

      // Latest balance should come from last APPROVED entry only
      const latestBalance =
        approvedStatements.length > 0
          ? approvedStatements.at(-1).balance
          : invoice.amount;

      const nextInterestDate =
        invoice.nextInterestApplicationDate ||
        getNextMonthEndDate(invoice.dueDate);

      return {
        ...invoice.toObject(),
        bankStatement: approvedStatements,
        latestBalance,
        nextInterestApplicationDate: nextInterestDate,
      };
    });

    return res.status(200).json({
      success: true,
      message:
        totalInvoices === 0
          ? "No invoices found for this buyer"
          : "Buyer invoices fetched successfully",
      pagination: {
        totalInvoices,
        currentPage: page,
        limit,
        totalPages: Math.ceil(totalInvoices / limit),
      },
      data: invoicesWithBalance,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// // Update credit entry (only by buyer)
// export const updateCredit = async (req, res) => {
//   try {
//     if (req.user.mode !== "buyer") {
//       return res
//         .status(403)
//         .json({ success: false, message: "Only buyers can update credit" });
//     }

//     const { id } = req.params; // bankStatement _id
//     const { credit } = req.body;

//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({ success: false, message: "Invalid ID" });
//     }

//     const invoice = await Invoice.findOne({ "bankStatement._id": id });
//     if (!invoice) {
//       return res
//         .status(404)
//         .json({ success: false, message: "Entry not found" });
//     }

//     const entry = invoice.bankStatement.id(id);
//     if (credit === undefined) {
//       return res
//         .status(400)
//         .json({ success: false, message: "Credit value required" });
//     }

//     entry.credit = credit;
//     await invoice.save();

//     return res.status(200).json({
//       success: true,
//       message: "Credit updated successfully",
//       data: entry,
//     });
//   } catch (error) {
//     console.error(error);
//     return res
//       .status(500)
//       .json({ success: false, message: "Internal server error" });
//   }
// };

// Update credit entry (only by buyer)
export const updateCredit = async (req, res) => {
  try {
    if (req.user.mode !== "buyer") {
      return res
        .status(403)
        .json({ success: false, message: "Only buyers can update credit" });
    }

    const { id } = req.params; // bankStatement _id
    const { credit } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid ID" });
    }

    const invoice = await Invoice.findOne({ "bankStatement._id": id });
    if (!invoice) {
      return res
        .status(404)
        .json({ success: false, message: "Entry not found" });
    }

    const entry = invoice.bankStatement.id(id);
    if (credit === undefined) {
      return res
        .status(400)
        .json({ success: false, message: "Credit value required" });
    }

    // Update the credit value
    entry.credit = credit;
    
    // Recalculate running balance for all entries
    let runningBalance = 0;
    
    // Sort entries by date (oldest first)
    const sortedEntries = [...invoice.bankStatement].sort((a, b) => 
      new Date(a.date) - new Date(b.date)
    );
    
    // Calculate new balances
    for (let i = 0; i < sortedEntries.length; i++) {
      const currentEntry = sortedEntries[i];
      if (i === 0) {
        // First entry: starting balance based on debit/credit
        runningBalance = currentEntry.debit - currentEntry.credit;
      } else {
        // Subsequent entries: add/subtract from previous balance
        runningBalance = runningBalance + currentEntry.debit - currentEntry.credit;
      }
      
      // Update the balance for this entry
      currentEntry.balance = runningBalance;
    }
    
    // Save the invoice
    await invoice.save();

    return res.status(200).json({
      success: true,
      message: "Credit updated successfully",
      data: entry,
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Update payment status (only by seller)
export const updatePaymentStatus = async (req, res) => {
  try {
    if (req.user.mode !== "seller") {
      return res
        .status(403)
        .json({
          success: false,
          message: "Only sellers can update payment status",
        });
    }

    const { id } = req.params; // bankStatement _id
    const { paymentStatus } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid ID" });
    }

    if (!paymentStatus) {
      return res
        .status(400)
        .json({ success: false, message: "paymentStatus required" });
    }

    const invoice = await Invoice.findOne({ "bankStatement._id": id });
    if (!invoice) {
      return res
        .status(404)
        .json({ success: false, message: "Entry not found" });
    }

    const entry = invoice.bankStatement.id(id);
    entry.paymentStatus = paymentStatus;

    await invoice.save();

    return res.status(200).json({
      success: true,
      message: "Payment status updated successfully",
      data: entry,
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// Delete bank statement entry (only by buyer)
export const deleteBankStatementEntry = async (req, res) => {
  try {
    const { invoiceId, bankStatementId } = req.body;

    const mode = req.user.mode;

    // Only allow if mode is 'buyer'
    if (mode !== "buyer") {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to delete this entry",
      });
    }

    // Find the invoice
    const invoice = await Invoice.findById(invoiceId);
    if (!invoice) {
      return res.status(404).json({
        success: false,
        message: "Invoice not found",
      });
    }

    // Remove the bankStatement entry
    const initialLength = invoice.bankStatement.length;
    invoice.bankStatement = invoice.bankStatement.filter(
      (entry) => entry._id.toString() !== bankStatementId
    );

    if (invoice.bankStatement.length === initialLength) {
      return res.status(404).json({
        success: false,
        message: "Bank statement entry not found",
      });
    }

    await invoice.save();

    res.status(200).json({
      success: true,
      message: "Bank statement entry deleted successfully",
      bankStatement: invoice.bankStatement,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// Get invoice by seller id and buyer id with (pagination)
// export const getInvoiceBySellerBuyer = async (req, res) => {
//   try {
//     const {
//       seller,
//       buyer,
//       page = 1,
//       limit = 10,
//     } = req.body;

//     // Validation
//     if (!seller && !buyer) {
//       return res.status(400).json({
//         success: false,
//         message: "seller or buyer is required",
//       });
//     }

//     const query = {};
//     if (seller) query.seller = seller;
//     if (buyer) query.buyer = buyer;

//     const skip = (Number(page) - 1) * Number(limit);

//     // Get invoices
//     const invoices = await Invoice.find(query)
//       .populate("order")
//       .populate("buyer")
//       .populate("seller")
//       .sort({ createdAt: -1 })
//       .skip(skip)
//       .limit(Number(limit));

//     const totalInvoices = await Invoice.countDocuments(query);

//     if (!invoices.length) {
//       return res.status(404).json({
//         success: false,
//         message: "No invoices found",
//       });
//     }

//     // Attach latest approved balance per invoice
//     const invoiceData = invoices.map((invoice) => {
//       const approvedStatements =
//         invoice.bankStatement?.filter(
//           (entry) => entry.paymentStatus === "Approved"
//         ) || [];

//       const latestBalance =
//         approvedStatements.length > 0
//           ? approvedStatements.at(-1).balance
//           : 0;

//       return {
//         ...invoice.toObject(),
//         latestBalance,
//         nextInterestApplicationDate:
//           invoice.nextInterestApplicationDate ||
//           getNextMonthEndDate(invoice.dueDate),
//       };
//     });

//     return res.status(200).json({
//       success: true,
//       message: "Invoices fetched successfully",
//       pagination: {
//         total: totalInvoices,
//         page: Number(page),
//         limit: Number(limit),
//         totalPages: Math.ceil(totalInvoices / limit),
//       },
//       data: invoiceData,
//     });
//   } catch (error) {
//     console.error("getInvoiceBySellerBuyer error:", error);
//     return res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       error: error.message,
//     });
//   }
// };

export const getInvoiceBySellerBuyer = async (req, res) => {
  try {
    const {
      seller,
      buyer,
      page = 1,
      limit = 10,
    } = req.body;

    if (!seller && !buyer) {
      return res.status(400).json({
        success: false,
        message: "seller or buyer is required",
      });
    }

    const query = {};
    if (seller) query.seller = seller;
    if (buyer) query.buyer = buyer;

    const skip = (Number(page) - 1) * Number(limit);

    const totalInvoices = await Invoice.countDocuments(query);

    const invoices = await Invoice.find(query)
      .populate("order", "items total")
      .populate("buyer", "name phone mode")
      .populate("seller", "name phone mode bankDetails")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit));

    if (!invoices.length) {
      return res.status(404).json({
        success: false,
        message: "No invoices found",
      });
    }

    const invoiceData = invoices.map((invoice) => {
      // ONLY approved statements
      const approvedStatements =
        invoice.bankStatement?.filter(
          (entry) => entry.paymentStatus === "Approved"
        ) || [];

      const latestBalance =
        approvedStatements.length > 0
          ? approvedStatements.at(-1).balance
          : invoice.amount;

      const nextInterestDate =
        invoice.nextInterestApplicationDate ||
        getNextMonthEndDate(invoice.dueDate);

      return {
        ...invoice.toObject(),
        bankStatement: approvedStatements,
        latestBalance,
        nextInterestApplicationDate: nextInterestDate,
      };
    });

    return res.status(200).json({
      success: true,
      message: "Invoices fetched successfully",
      pagination: {
        totalInvoices,
        currentPage: Number(page),
        limit: Number(limit),
        totalPages: Math.ceil(totalInvoices / limit),
      },
      data: invoiceData,
    });
  } catch (error) {
    console.error("getInvoiceBySellerBuyer error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// My Fix corn job 
// APPLY MONTHLY INTEREST - FIXED VERSION
export const applyMonthlyInterestIfNeeded = async (
  invoice,
  runAt = new Date()
) => {
  if (invoice.status === "Paid") return;

  const today = startOfDay(runAt);
  if (!isLastDayOfMonth(today)) return;
  if (!invoice.dueDate || !invoice.interestRatePerYear) return;

  const dueDate = startOfDay(new Date(invoice.dueDate));
  if (today < dueDate) return;

  const monthName = today.toLocaleString("default", {
    month: "long",
    year: "numeric",
  });
  const interestDesc = `Monthly interest for ${monthName}`;

  const alreadyApplied = invoice.bankStatement.some(
    (txn) => txn.description === interestDesc
  );
  if (alreadyApplied) return;

  const interest = calculateDailyInterestForPeriod(invoice, dueDate, today);
  if (interest <= 0) return;

  // Get last APPROVED balance (not pending payments)
  const approvedStatements = invoice.bankStatement.filter(
    (entry) => entry.paymentStatus === "Approved"
  );
  const lastBalance = approvedStatements.length > 0 
    ? approvedStatements.at(-1).balance 
    : invoice.amount;
  
  const newBalance = +(lastBalance + interest).toFixed(2);

  // FIX: Interest entries should be AUTO-APPROVED
  invoice.bankStatement.push({
    date: endOfDay(today),
    description: interestDesc,
    debit: interest,
    credit: 0,
    balance: newBalance,
    paymentStatus: "Approved", // AUTO-APPROVED (not Pending)
  });

  invoice.status = "Overdue";
  invoice.lastMonthEndInterestApplied = endOfDay(today);
  invoice.nextInterestApplicationDate = getNextMonthEndDate(endOfDay(today));
  invoice.markModified("bankStatement");
  await invoice.save();
  
  console.log(`✅ Interest applied for invoice ${invoice._id}: ₹${interest}`);
};

// BALANCE HELPER (Interest entries bittu balance nodalu)
const getBalanceOnDate = (invoice, date) => {
  const targetDate = startOfDay(new Date(date));
  let balance = invoice.amount;

  // Filter only APPROVED entries (excluding pending payments AND interest)
  const sortedStatements = [...invoice.bankStatement]
    .filter((entry) => entry.paymentStatus === "Approved" && 
                      !entry.description.toLowerCase().includes("interest"))
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  for (const entry of sortedStatements) {
    if (startOfDay(new Date(entry.date)) <= targetDate) {
      balance = entry.balance;
    } else {
      break;
    }
  }
  return balance;
};

// DAILY INTEREST HELPER (Leap Year Optimized)
const calculateDailyInterestForPeriod = (invoice, startDate, endDate) => {
  const ratePerYear = (invoice.interestRatePerYear || 0) / 100;

  // Filter only APPROVED payments (not pending)
  const payments = [...invoice.bankStatement]
    .filter((txn) => txn.paymentStatus === "Approved" && 
                     !txn.description.toLowerCase().includes("interest"))
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  let totalInterest = 0;
  let periodStart = startOfDay(new Date(startDate));
  const finalEnd = startOfDay(new Date(endDate));
  let currentBalance = getBalanceOnDate(invoice, startDate);

  for (const txn of payments) {
    const txnDate = startOfDay(new Date(txn.date));

    if (txnDate > periodStart && txnDate <= finalEnd) {
      const days = differenceInCalendarDays(txnDate, periodStart);
      if (days > 0) {
        const dailyRate = ratePerYear / getDaysInYear(periodStart);
        totalInterest += currentBalance * dailyRate * days;
      }
      currentBalance = txn.balance;
      periodStart = txnDate;
    }
  }

  const remainingDays = differenceInCalendarDays(finalEnd, periodStart);
  if (remainingDays > 0) {
    const dailyRate = ratePerYear / getDaysInYear(periodStart);
    totalInterest += currentBalance * dailyRate * remainingDays;
  }

  return +totalInterest.toFixed(2);
};

// export const runMonthlyInterestForAll = async (runAt = new Date()) => {
//   // Only run on month-end dates
//   if (!isLastDayOfMonth(runAt)) {
//     console.log(`Not a month-end date: ${runAt.toISOString()}`);
//     return;
//   }

//   const today = startOfDay(runAt);
  
//   // Find invoices that:
//   // 1. Are not paid
//   // 2. Have dueDate passed
//   // 3. Have interest rate > 0
//   // 4. Haven't already had interest applied for this month
//   const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
  
//   const invoices = await Invoice.find({
//     status: { $ne: "Paid" },
//     dueDate: { $lte: today },
//     interestRatePerYear: { $gt: 0 },
//     $or: [
//       { lastMonthEndInterestApplied: { $lt: startOfMonth } },
//       { lastMonthEndInterestApplied: null }
//     ]
//   });

//   console.log(
//     `Running monthly interest for ${
//       invoices.length
//     } invoices on ${runAt.toISOString()}`
//   );

//   for (const inv of invoices) {
//     try {
//       await applyMonthlyInterestIfNeeded(inv, runAt);
//     } catch (error) {
//       console.error(`Failed to apply interest for invoice ${inv._id}: ${error.message}`);
//     }
//   }

//   console.log(`Monthly interest application completed`);
// };


// invoiceController.js में

export const runMonthlyInterestForAll = async (runAt = new Date()) => {
  console.log('🔔 runMonthlyInterestForAll called with date:', runAt);
  console.log('Input date ISO:', runAt.toISOString());
  
  // दिए गए date को IST में convert करें
  const istDate = new Date(
    runAt.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
  );
  
  console.log('After IST conversion:', istDate.toString());
  
  // IST के हिसाब से check करें
  const lastDayOfMonth = new Date(
    istDate.getFullYear(),
    istDate.getMonth() + 1,
    0
  ).getDate();
  
  const isLastDay = istDate.getDate() === lastDayOfMonth;
  
  if (!isLastDay) {
    console.log(`❌ Not a month-end date in IST: ${istDate.toLocaleDateString()}`);
    console.log(`Today: ${istDate.getDate()}, Last day: ${lastDayOfMonth}`);
    return;
  }

  console.log(`✅ Date is month-end in IST: ${istDate.toLocaleDateString()}`);
  
  // Start of day in IST
  const todayIST = startOfDay(istDate);
  
  console.log(`🔍 Looking for invoices with dueDate <= ${todayIST.toISOString()}`);
  
  // Find invoices
  const invoices = await Invoice.find({
    status: { $ne: "Paid" },
    dueDate: { $lte: todayIST },
    interestRatePerYear: { $gt: 0 }
  });

  console.log(`📊 Found ${invoices.length} invoices for interest calculation`);
  
  for (const inv of invoices) {
    try {
      console.log(`\n🔄 Processing invoice: ${inv._id}`);
      console.log(`   Due date: ${inv.dueDate}`);
      console.log(`   Current balance: ${inv.bankStatement.at(-1)?.balance || inv.amount}`);
      
      // Check if interest already applied for this month
      const monthStart = new Date(istDate.getFullYear(), istDate.getMonth(), 1);
      const lastApplied = inv.lastMonthEndInterestApplied;
      
      if (lastApplied && lastApplied >= monthStart) {
        console.log(`   ⏭️ Interest already applied this month on: ${lastApplied}`);
        continue;
      }
      
      await applyMonthlyInterestIfNeeded(inv, istDate);
      console.log(`   ✅ Interest applied successfully`);
      
    } catch (error) {
      console.error(`   ❌ Failed for invoice ${inv._id}: ${error.message}`);
    }
  }

  console.log(`🎯 Monthly interest application completed for ${invoices.length} invoices`);
};

// invoiceController.js में
export const testMonthEndInterest = async (req, res) => {
  try {
    const { date } = req.body; // Format: "2026-01-31"
    
    // Use provided date or current date
    let testDate;
    if (date) {
      // Create date in IST timezone
      testDate = new Date(date + 'T00:00:00.000+05:30');
    } else {
      // Current IST date
      const now = new Date();
      testDate = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" }));
    }
    
    console.log('\n🧪 TEST: Monthly Interest Calculation');
    console.log('Test Date:', testDate.toString());
    console.log('Test Date ISO:', testDate.toISOString());
    
    // Check if it's month end
    const lastDay = new Date(
      testDate.getFullYear(),
      testDate.getMonth() + 1,
      0
    ).getDate();
    
    const isLastDay = testDate.getDate() === lastDay;
    
    if (!isLastDay) {
      return res.json({
        success: false,
        message: `Not month end. Date: ${testDate.getDate()}, Last day: ${lastDay}`,
        testDate: testDate.toISOString(),
        isMonthEnd: false
      });
    }
    
    // Run interest calculation
    console.log('✅ This is month end, running interest calculation...');
    await runMonthlyInterestForAll(testDate);
    
    res.json({
      success: true,
      message: `Interest calculation run for ${testDate.toLocaleDateString()}`,
      testDate: testDate.toISOString(),
      isMonthEnd: true
    });
    
  } catch (error) {
    console.error('Test error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
};
