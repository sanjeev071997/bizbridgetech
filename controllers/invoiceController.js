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
export const recordPayment = async (req, res) => {
  try {
    const { id } = req.params;
    let { amount, paidAt, note } = req.body;

    amount = Number(amount);

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Amount must be greater than 0",
      });
    }

    const invoice = await Invoice.findById(id);

    if (!invoice) {
      return res.status(404).json({
        success: false,
        message: "Invoice not found",
      });
    }

    // ❌ Block if pending approval exists
    const hasPending = invoice.bankStatement.some(
      (entry) => entry.paymentStatus === "Pending"
    );

    if (hasPending) {
      return res.status(400).json({
        success: false,
        message:
          "Previous payment is pending seller approval.",
      });
    }

    // Safe last balance
    const lastBalance =
      invoice.bankStatement.length > 0
        ? Number(invoice.bankStatement.at(-1).balance)
        : Number(invoice.amount);

    if (amount > lastBalance) {
      return res.status(400).json({
        success: false,
        message: `Payment cannot exceed remaining balance (${lastBalance})`,
      });
    }

    // Safe Date
    let paymentDate = paidAt ? new Date(paidAt) : new Date();
    if (isNaN(paymentDate.getTime())) {
      paymentDate = new Date();
    }

    const paidAmount =
      Math.round((amount + Number.EPSILON) * 100) / 100;

    const newBalance =
      Math.round(
        (lastBalance - paidAmount + Number.EPSILON) * 100
      ) / 100;

    invoice.bankStatement.push({
      date: paymentDate,
      description: note || "Payment received",
      debit: 0,
      credit: paidAmount,
      balance: newBalance,
      paymentStatus: "Pending",
    });

    // Update invoice status
    if (newBalance <= 0) {
      invoice.status = "Paid";
      invoice.paidAt = paymentDate;
    } else if (
      invoice.dueDate &&
      new Date() > new Date(invoice.dueDate)
    ) {
      invoice.status = "Overdue";
    } else {
      invoice.status = "Pending";
    }

    await invoice.save();

    res.status(200).json({
      success: true,
      message:
        "Payment recorded successfully and waiting for seller approval",
      data: invoice,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
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

// Update credit entry (only by buyer)
export const updateCredit = async (req, res) => {
  try {
    if (req.user.mode !== "buyer") {
      return res.status(403).json({
        success: false,
        message: "Only buyers can update credit",
      });
    }

    const { id } = req.params;
    let { credit } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid ID",
      });
    }

    credit = Number(credit);

    if (credit === undefined || isNaN(credit) || credit < 0) {
      return res.status(400).json({
        success: false,
        message: "Valid credit value required",
      });
    }

    const invoice = await Invoice.findOne({ "bankStatement._id": id });

    if (!invoice) {
      return res.status(404).json({
        success: false,
        message: "Entry not found",
      });
    }

    const entry = invoice.bankStatement.id(id);

    if (!entry) {
      return res.status(404).json({
        success: false,
        message: "Bank entry not found",
      });
    }

    // Update credit safely
    entry.credit = credit;
    entry.debit = 0;

    // 🔥 Recalculate Running Balance Properly
    let runningBalance = Number(invoice.amount) || 0;

    const sortedEntries = invoice.bankStatement
      .slice()
      .sort(
        (a, b) =>
          new Date(a.date || 0).getTime() -
          new Date(b.date || 0).getTime()
      );

    for (let item of sortedEntries) {
      const debit = Number(item.debit) || 0;
      const creditVal = Number(item.credit) || 0;

      runningBalance =
        runningBalance + debit - creditVal;

      item.balance =
        Math.round((runningBalance + Number.EPSILON) * 100) / 100;
    }

    // Update invoice status
    if (runningBalance <= 0) {
      invoice.status = "Paid";
      invoice.paidAt = new Date();
    } else if (
      invoice.dueDate &&
      new Date() > new Date(invoice.dueDate)
    ) {
      invoice.status = "Overdue";
    } else {
      invoice.status = "Pending";
    }

    await invoice.save();

    return res.status(200).json({
      success: true,
      message: "Credit updated and balance recalculated successfully",
      data: entry,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
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

// Manual trigger API
export const runInterestCronNow = async (req, res) => {
  await runMonthlyInterestForAll(new Date());
  res.json({ success: true, message: "Monthly interest run executed" });
};

// BALANCE HELPER - किसी specific date पर balance निकालो
const getBalanceOnDate = (invoice, date) => {
  const targetDate = startOfDay(new Date(date));
  
  // सारे approved transactions जो targetDate से पहले या उस दिन हुए
  const relevantTransactions = [...invoice.bankStatement]
    .filter((txn) => 
      txn.paymentStatus === "Approved" && 
      startOfDay(new Date(txn.date)) <= targetDate
    )
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  if (relevantTransactions.length === 0) {
    return invoice.amount;
  }

  // Last transaction का balance लो
  return relevantTransactions.at(-1).balance;
};

// APPLY MONTHLY INTEREST 
export const applyMonthlyInterestIfNeeded = async (
  invoice,
  runAt = new Date()
) => {
  if (invoice.status === "Paid") return;

  const today = startOfDay(runAt);
  
  // IMPORTANT: Check if today is last day of month (using IST)
  if (!isLastDayOfMonth(today)) {
    console.log(` Not last day of month: ${today.toLocaleDateString()}`);
    return;
  }
  
  if (!invoice.dueDate || !invoice.interestRatePerYear) {
    console.log(` No dueDate or interestRate: ${invoice._id}`);
    return;
  }

  const dueDate = startOfDay(new Date(invoice.dueDate));
  
  // Only apply interest if due date has passed
  // if (today < dueDate) {
  //   console.log(`   ⏭️ Due date not passed: ${dueDate.toLocaleDateString()}`);
  //   return;
  // }

  const monthName = today.toLocaleString("default", {
    month: "long",
    year: "numeric",
  });
  
  // Check for multiple possible description formats
  const possibleDescriptions = [
    `Monthly interest for ${monthName}`,
    `Monthly interest`,
    `Interest for ${monthName}`,
    `Month-end interest`
  ];
  
  const alreadyApplied = invoice.bankStatement.some(
    (txn) => possibleDescriptions.some(desc => txn.description.includes(desc))
  );
  
  if (alreadyApplied) {
    console.log(`   ⏭️ Interest already applied for ${monthName}`);
    return;
  }

  // Get last APPROVED balance (excluding pending payments but INCLUDING interest entries)
  const approvedStatements = invoice.bankStatement.filter(
    (entry) => entry.paymentStatus === "Approved"
  );
  
  const lastBalance = approvedStatements.length > 0 
    ? approvedStatements.at(-1).balance 
    : invoice.amount;
  
  // Calculate interest from due date to today
  const interest = calculateDailyInterestForPeriod(invoice, dueDate, today);
  
  if (interest <= 0) {
    console.log(`   ℹ️ No interest to apply (interest <= 0)`);
    return;
  }

  const newBalance = +(lastBalance + interest).toFixed(2);

  // Add interest entry with APPROVED status
  invoice.bankStatement.push({
    date: endOfDay(today),
    description: `Monthly interest for ${monthName}`,
    debit: interest,
    credit: 0,
    balance: newBalance,
    paymentStatus: "Approved", // Auto-approved
  });

  invoice.status = "Overdue";
  invoice.lastMonthEndInterestApplied = endOfDay(today);
  
  // Calculate next month's end date
  const nextMonth = new Date(today);
  nextMonth.setMonth(nextMonth.getMonth() + 1);
  invoice.nextInterestApplicationDate = getMonthEndDate(nextMonth);
  
  invoice.markModified("bankStatement");
  await invoice.save();
  
  // console.log(`✅ Interest applied for invoice ${invoice._id}: ₹${interest}`);
};

// DAILY INTEREST HELPER
const calculateDailyInterestForPeriod = (invoice, startDate, endDate) => {
  const ratePerYear = (invoice.interestRatePerYear || 0) / 100;

  // Get ALL approved transactions in chronological order
  const approvedTransactions = [...invoice.bankStatement]
    .filter((txn) => txn.paymentStatus === "Approved")
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  let totalInterest = 0;
  let periodStart = startOfDay(new Date(startDate));
  const finalEnd = startOfDay(new Date(endDate));
  
  // console.log(`   📅 Period: ${periodStart.toLocaleDateString()} to ${finalEnd.toLocaleDateString()}`);
  
  // Get initial balance at startDate
  let currentBalance = getBalanceOnDate(invoice, startDate);
  // console.log(`   💰 Initial Balance on ${periodStart.toLocaleDateString()}: ₹${currentBalance}`);
  
  // Get all transactions that fall within this period
  const relevantTransactions = approvedTransactions.filter(txn => {
    const txnDate = startOfDay(new Date(txn.date));
    return txnDate > periodStart && txnDate <= finalEnd;
  });
  
  console.log(`   📊 Found ${relevantTransactions.length} transactions in this period`);
  
  // Case 1: कोई transaction नहीं है period में
  if (relevantTransactions.length === 0) {
    const days = differenceInCalendarDays(finalEnd, periodStart);
    // अगर same day है तो 1 day
    const actualDays = days === 0 ? 1 : days;
    
    const dailyRate = ratePerYear / getDaysInYear(periodStart);
    const periodInterest = currentBalance * dailyRate * actualDays;
    totalInterest += periodInterest;
    
    console.log(`   📊 No transactions: ${currentBalance} × ${ratePerYear*100}% × ${actualDays}/365 = ₹${periodInterest.toFixed(2)}`);
    
    return +totalInterest.toFixed(2);
  }
  
  // Case 2: Transactions हैं - हर transaction के बीच का interest calculate करो
  let lastProcessedDate = periodStart;
  
  for (const txn of relevantTransactions) {
    const txnDate = startOfDay(new Date(txn.date));
    
    // पिछले date से इस transaction date तक का interest
    const days = differenceInCalendarDays(txnDate, lastProcessedDate);
    if (days > 0) {
      const dailyRate = ratePerYear / getDaysInYear(lastProcessedDate);
      const periodInterest = currentBalance * dailyRate * days;
      totalInterest += periodInterest;
      
      console.log(`   📊 ${lastProcessedDate.toLocaleDateString()} to ${txnDate.toLocaleDateString()}:`);
      console.log(`      Balance: ₹${currentBalance} × ${ratePerYear*100}% × ${days} days = ₹${periodInterest.toFixed(2)}`);
    }
    
    // Transaction के बाद balance update करो
    currentBalance = txn.balance;
    lastProcessedDate = txnDate;
    
    console.log(`   💰 After transaction on ${txnDate.toLocaleDateString()}: New Balance = ₹${currentBalance}`);
  }
  
  // Last transaction से endDate तक का interest
  if (lastProcessedDate < finalEnd) {
    const days = differenceInCalendarDays(finalEnd, lastProcessedDate);
    const actualDays = days === 0 ? 1 : days;
    
    if (actualDays > 0) {
      const dailyRate = ratePerYear / getDaysInYear(lastProcessedDate);
      const remainingInterest = currentBalance * dailyRate * actualDays;
      totalInterest += remainingInterest;
      
      console.log(`   📊 ${lastProcessedDate.toLocaleDateString()} to ${finalEnd.toLocaleDateString()}:`);
      console.log(`      Balance: ₹${currentBalance} × ${ratePerYear*100}% × ${actualDays} days = ₹${remainingInterest.toFixed(2)}`);
    }
  }

  console.log(`   💰 TOTAL INTEREST for period: ₹${totalInterest.toFixed(2)}`);
  
  return +totalInterest.toFixed(2);
};

export const runMonthlyInterestForAll = async (runAt = new Date()) => {
  console.log('\n🔔 ========== MONTHLY INTEREST RUN STARTED ==========');
  console.log('📅 Input date (UTC):', runAt.toISOString());
  console.log('📅 Input date (Local):', runAt.toString());
  
  // Convert to IST
  const istDate = new Date(
    runAt.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
  );
  console.log('📅 IST date:', istDate.toString());
  console.log('📅 IST date components:', {
    year: istDate.getFullYear(),
    month: istDate.getMonth() + 1,
    date: istDate.getDate(),
    hours: istDate.getHours(),
    minutes: istDate.getMinutes()
  });

  // निकालो कि किस महीने के लिए interest लगाना है
  let targetMonth;
  let isFirstDayOfMonth = istDate.getDate() === 1;
  
  if (isFirstDayOfMonth) {
    // अगर 1 तारीख है, तो पिछले महीने का interest लगाओ
    targetMonth = new Date(istDate);
    targetMonth.setMonth(targetMonth.getMonth() - 1);
    console.log(`📅 1st of month detected - applying interest for PREVIOUS month: ${targetMonth.toLocaleDateString()}`);
  } else {
    // नहीं तो इसी महीने का
    targetMonth = new Date(istDate);
    console.log(`📅 Applying interest for CURRENT month: ${targetMonth.toLocaleDateString()}`);
  }

  // Target month के आखिरी दिन की date बनाओ
  const targetMonthEnd = new Date(
    targetMonth.getFullYear(),
    targetMonth.getMonth() + 1,
    0,
    23,
    59,
    59
  );
  
  console.log(`🎯 Target month end date for interest calculation: ${targetMonthEnd.toLocaleDateString()}`);
  console.log(`🎯 Target month end ISO: ${targetMonthEnd.toISOString()}`);
  
  // सारे unpaid invoices ढूंढो (interest rate > 0 वाले)
  console.log('\n🔍 Fetching all unpaid invoices with interest rate > 0...');
  
  const invoices = await Invoice.find({
    status: { $ne: "Paid" },
    interestRatePerYear: { $gt: 0 }
  });

  console.log(`📊 Found ${invoices.length} total unpaid invoices`);
  
  // हर invoice की डिटेल दिखाओ
  console.log('\n📋 ELIGIBLE INVOICES LIST:');
  invoices.forEach((inv, index) => {
    console.log(`\n${index + 1}. Invoice ID: ${inv._id}`);
    console.log(`   Amount: ₹${inv.amount}`);
    console.log(`   Due Date: ${inv.dueDate ? new Date(inv.dueDate).toLocaleDateString() : 'Not set'}`);
    console.log(`   Interest Rate: ${inv.interestRatePerYear}%`);
    console.log(`   Status: ${inv.status}`);
    
    // Current balance निकालो
    const approvedStatements = inv.bankStatement.filter(e => e.paymentStatus === "Approved");
    const currentBalance = approvedStatements.length > 0 ? approvedStatements.at(-1).balance : inv.amount;
    console.log(`   Current Balance: ₹${currentBalance}`);
    
    // Last 3 bank statements दिखाओ
    console.log(`   Recent Transactions:`);
    const lastEntries = inv.bankStatement.slice(-3);
    lastEntries.forEach(entry => {
      console.log(`     - ${new Date(entry.date).toLocaleDateString()}: ${entry.description} | ₹${entry.debit > 0 ? 'Debit: ' + entry.debit : 'Credit: ' + entry.credit} | Balance: ₹${entry.balance} | Status: ${entry.paymentStatus}`);
    });
  });

  console.log('\n🔄 PROCESSING EACH INVOICE FOR INTEREST:');
  
  let appliedCount = 0;
  let skippedCount = 0;
  let dueDateNotPassedCount = 0;
  let alreadyAppliedCount = 0;
  let noDueDateCount = 0;  // <-- यह वेरिएबल डिफाइन करना था
  
  for (const inv of invoices) {
    try {
      console.log(`\n🔍 INVOICE: ${inv._id}`);
      console.log(`   ========================================`);
      
      // Skip if no due date
      if (!inv.dueDate) {
        console.log(`   ❌ SKIPPED: No due date set`);
        noDueDateCount++;
        skippedCount++;
        continue;
      }
      
      const dueDate = startOfDay(new Date(inv.dueDate));
      const targetDate = startOfDay(targetMonthEnd);
      
      console.log(`   📅 Due Date: ${dueDate.toLocaleDateString()}`);
      console.log(`   📅 Target Date: ${targetDate.toLocaleDateString()}`);
      
      // Check if due date has passed target month end
      if (dueDate > targetDate) {
        console.log(`   ⏭️ SKIPPED: Due date (${dueDate.toLocaleDateString()}) is after target month end (${targetDate.toLocaleDateString()})`);
        dueDateNotPassedCount++;
        skippedCount++;
        continue;
      }
      
      // Check if interest already applied for this month
      const monthYear = targetMonth.toLocaleString("default", {
        month: "long",
        year: "numeric",
      });
      
      console.log(`   🔍 Checking if interest already applied for: ${monthYear}`);
      
      const alreadyApplied = inv.bankStatement.some(
        (txn) => txn.description && txn.description.includes(monthYear)
      );
      
      if (alreadyApplied) {
        console.log(`   ⏭️ SKIPPED: Interest already applied for ${monthYear}`);
        alreadyAppliedCount++;
        skippedCount++;
        
        // Show the interest entry that was already applied
        const interestEntry = inv.bankStatement.find(txn => txn.description && txn.description.includes(monthYear));
        if (interestEntry) {
          console.log(`   📝 Existing interest entry: ₹${interestEntry.debit} applied on ${new Date(interestEntry.date).toLocaleDateString()}`);
        }
        continue;
      }
      
      // Get current balance
      const approvedStatements = inv.bankStatement.filter(e => e.paymentStatus === "Approved");
      const currentBalance = approvedStatements.length > 0 ? approvedStatements.at(-1).balance : inv.amount;
      console.log(`   💰 Current Balance: ₹${currentBalance}`);
      
      // Calculate interest
      console.log(`   🧮 Calculating interest from ${dueDate.toLocaleDateString()} to ${targetDate.toLocaleDateString()}...`);
      
      const interest = calculateDailyInterestForPeriod(inv, dueDate, targetDate);
      
      console.log(`   📊 Calculated Interest: ₹${interest}`);
      
      if (interest <= 0.01) {
        console.log(`   ℹ️ SKIPPED: No interest to calculate (interest <= 0.01)`);
        skippedCount++;
        continue;
      }
      
      // Apply interest
      const newBalance = +(currentBalance + interest).toFixed(2);
      console.log(`   💰 New Balance after interest: ₹${newBalance}`);
      
      const interestEntry = {
        date: endOfDay(targetMonthEnd),
        description: `Monthly interest for ${monthYear}`,
        debit: interest,
        credit: 0,
        balance: newBalance,
        paymentStatus: "Approved",
      };
      
      inv.bankStatement.push(interestEntry);
      inv.status = "Overdue";
      inv.lastMonthEndInterestApplied = endOfDay(targetMonthEnd);
      
      // Calculate next month's end date
      const nextMonth = new Date(targetMonthEnd);
      nextMonth.setMonth(nextMonth.getMonth() + 1);
      inv.nextInterestApplicationDate = getMonthEndDate(nextMonth);
      
      inv.markModified("bankStatement");
      await inv.save();
      
      console.log(`   ✅ SUCCESS: Interest applied: ₹${interest}`);
      console.log(`   📝 New bank statement entry added:`);
      console.log(`      - Date: ${interestEntry.date.toLocaleDateString()}`);
      console.log(`      - Description: ${interestEntry.description}`);
      console.log(`      - Debit: ₹${interestEntry.debit}`);
      console.log(`      - New Balance: ₹${interestEntry.balance}`);
      
      appliedCount++;
      
    } catch (error) {
      console.error(`   ❌ ERROR for invoice ${inv._id}:`, error.message);
      console.error(error.stack);
      skippedCount++;
    }
  }

  console.log('\n📊 ========== FINAL SUMMARY ==========');
  console.log(`✅ Interest Applied: ${appliedCount} invoices`);
  console.log(`⏭️ Skipped (No due date): ${noDueDateCount}`);
  console.log(`⏭️ Skipped (Due date not passed): ${dueDateNotPassedCount}`);
  console.log(`⏭️ Skipped (Already applied): ${alreadyAppliedCount}`);
  console.log(`⏭️ Skipped (Other reasons): ${skippedCount - noDueDateCount - dueDateNotPassedCount - alreadyAppliedCount}`);
  console.log(`📊 Total Processed: ${invoices.length} invoices`);
  console.log('=========================================\n');
  
  // अगर कोई invoice eligible थी तो उनकी लिस्ट दिखाओ
  if (appliedCount > 0) {
    console.log('✅ INVOICES THAT RECEIVED INTEREST:');
    const updatedInvoices = await Invoice.find({
      _id: { $in: invoices.slice(0, appliedCount).map(inv => inv._id) }
    });
    updatedInvoices.forEach(inv => {
      const lastEntry = inv.bankStatement.at(-1);
      if (lastEntry && lastEntry.description.includes('Monthly interest')) {
        console.log(`   - ${inv._id}: ₹${lastEntry.debit} interest applied, New balance: ₹${lastEntry.balance}`);
      }
    });
  }
  
  return { appliedCount, skippedCount, dueDateNotPassedCount, alreadyAppliedCount, noDueDateCount };
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


