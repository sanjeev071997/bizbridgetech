import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import mongoose from "mongoose";
import Order from "../models/orderModel.js";
import Invoice from "../models/invoiceModel.js";
import BuyerSellerConnection from '../models/buyerSellerConnectionModels.js';
import Support from "../models/supportModel.js"
import User from "../models/userModel.js"
import Product from "../models/sellerProductModel.js";
import BuyerCategory from "../models/buyerCategoriesModel.js"
import SellerCategory from "../models/sellercategoriesModel.js"
import Contact from "../models/contactModel.js"

// Seller Dashboard
export const sellerDashboard = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { days } = req.query; 
    
    const filterDays = parseInt(days) || 7; 
    const now = new Date();
    const timeLimit = new Date();
    timeLimit.setDate(timeLimit.getDate() - filterDays);
    timeLimit.setHours(0, 0, 0, 0); 

    // --- 1. Growth Calculation (Current Month vs Last Month) ---
    const startOfCurrentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0);

    const [currentMonthRev, lastMonthRev] = await Promise.all([
      Order.aggregate([
        { $match: { "items.seller": userId, orderStatus: "Completed", createdAt: { $gte: startOfCurrentMonth } } },
        { $group: { _id: null, total: { $sum: "$total" } } }
      ]),
      Order.aggregate([
        { $match: { "items.seller": userId, orderStatus: "Completed", createdAt: { $gte: startOfLastMonth, $lte: endOfLastMonth } } },
        { $group: { _id: null, total: { $sum: "$total" } } }
      ])
    ]);

    const currentRevValue = currentMonthRev[0]?.total || 0;
    const lastRevValue = lastMonthRev[0]?.total || 0;
    let growthPercentage = lastRevValue > 0 ? ((currentRevValue - lastRevValue) / lastRevValue) * 100 : (currentRevValue > 0 ? 100 : 0);

    // --- 2. Main Stats Data ---
    const [
      totalReceivables,
      ordersInTransit,
      overdueInvoices,
      pendingRequests,
      revenueStats,
      liveFeedOrders,
      allInvoicesForFeed
    ] = await Promise.all([
      Invoice.aggregate([
        { $match: { seller: userId, status: "Pending", createdAt: { $gte: timeLimit } } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
      ]),
      Order.countDocuments({ "items.seller": userId, orderStatus: { $in: ["Processing", "Shipped", "Pending"] }, createdAt: { $gte: timeLimit } }),
      Invoice.countDocuments({ seller: userId, status: "Pending", dueDate: { $lt: new Date() }, createdAt: { $gte: timeLimit } }),
      BuyerSellerConnection.countDocuments({ seller: userId, status: "Pending" }),
      Order.aggregate([
        { $match: { "items.seller": userId, orderStatus: "Completed", createdAt: { $gte: new Date(new Date().setMonth(now.getMonth() - 6)) } } },
        { $group: { _id: { month: { $month: "$createdAt" }, year: { $year: "$createdAt" } }, revenue: { $sum: "$total" } } },
        { $sort: { "_id.year": 1, "_id.month": 1 } }
      ]),
      Order.find({ "items.seller": userId }).populate("buyer", "name").sort({ createdAt: -1 }).limit(5),
      Invoice.find({ seller: userId }).populate("buyer", "name").sort({ updatedAt: -1 }).limit(5)
    ]);

    // Format Receivables to 2 Decimal Places
    const finalTotalReceivables = Number((totalReceivables[0]?.total || 0).toFixed(2));

    // Format Graph Data to 2 Decimal Places
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const formattedGraphData = revenueStats.map(item => ({
      name: monthNames[item._id.month - 1],
      revenue: Number((item.revenue / 1000).toFixed(2))
    }));

    // --- 3. Live Feed Logic ---
    const paymentEntries = [];
    allInvoicesForFeed.forEach(inv => {
      if (inv.bankStatement && inv.bankStatement.length > 1) {
        inv.bankStatement.slice(1).forEach(entry => {
          if (entry.credit > 0) {
            paymentEntries.push({
              id: entry._id,
              name: inv.buyer?.name || "Unknown Buyer",
              action: entry.description || "Payment received",
              time: entry.date,
              amount: `+₹${entry.credit.toFixed(2)}`,
              type: "payment"
            });
          }
        });
      }
    });

    const orderEntries = liveFeedOrders.map(o => ({
      id: o._id,
      name: o.buyer?.name || "Unknown Buyer",
      action: "placed an order.",
      time: o.createdAt,
      amount: `₹${o.total.toFixed(2)}`,
      type: "order"
    }));

    const liveFeed = [...orderEntries, ...paymentEntries]
      .sort((a, b) => new Date(b.time) - new Date(a.time))
      .slice(0, 5); 

    return res.json({
      success: true,
      data: {
        businessGrowth: Math.round(growthPercentage),
        totalReceivables: finalTotalReceivables,
        ordersInTransit,
        overdueInvoices,
        pendingRequests,
        graphData: formattedGraphData,
        liveFeed
      }
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Buyer Dashboard
export const buyerDashboard = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { days } = req.query; 
    
    const filterDays = parseInt(days) || 7; 
    const now = new Date();
    const timeLimit = new Date();
    timeLimit.setDate(timeLimit.getDate() - filterDays);
    timeLimit.setHours(0, 0, 0, 0); 

    // --- 1. Growth Calculation (Current Month Expense vs Last Month Expense) ---
    const startOfCurrentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0);

    const [currentMonthExp, lastMonthExp] = await Promise.all([
      Order.aggregate([
        { $match: { buyer: userId, orderStatus: "Completed", createdAt: { $gte: startOfCurrentMonth } } },
        { $group: { _id: null, total: { $sum: "$total" } } }
      ]),
      Order.aggregate([
        { $match: { buyer: userId, orderStatus: "Completed", createdAt: { $gte: startOfLastMonth, $lte: endOfLastMonth } } },
        { $group: { _id: null, total: { $sum: "$total" } } }
      ])
    ]);

    const currentExpValue = currentMonthExp[0]?.total || 0;
    const lastExpValue = lastMonthExp[0]?.total || 0;
    let growthPercentage = lastExpValue > 0 ? ((currentExpValue - lastExpValue) / lastExpValue) * 100 : (currentExpValue > 0 ? 100 : 0);

    // --- 2. Main Stats Data ---
    const [
      totalPayables,
      ordersInTransit,
      pendingInvoicesCount,
      totalSellers,
      expenseStats,
      liveFeedOrders,
      allInvoicesForFeed
    ] = await Promise.all([
      // Total Payables (Pending Invoices amount)
      Invoice.aggregate([
        { $match: { buyer: userId, status: "Pending", createdAt: { $gte: timeLimit } } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
      ]),
      // Orders in Transit / Processing
      Order.countDocuments({ buyer: userId, orderStatus: { $in: ["Processing", "Shipped", "Pending"] }, createdAt: { $gte: timeLimit } }),
      // Pending Invoices Count
      Invoice.countDocuments({ buyer: userId, status: "Pending", createdAt: { $gte: timeLimit } }),
      // Total Connections
      BuyerSellerConnection.countDocuments({ buyer: userId, status: "Accepted" }),
      // Graph Data: Last 6 Months Expense
      Order.aggregate([
        { $match: { buyer: userId, orderStatus: "Completed", createdAt: { $gte: new Date(new Date().setMonth(now.getMonth() - 6)) } } },
        { $group: { _id: { month: { $month: "$createdAt" }, year: { $year: "$createdAt" } }, expense: { $sum: "$total" } } },
        { $sort: { "_id.year": 1, "_id.month": 1 } }
      ]),
      // Recent Orders for Feed
      Order.find({ buyer: userId }).populate({ path: "items.seller", select: "name" }).sort({ createdAt: -1 }).limit(5),
      // Recent Invoice Payments for Feed
      Invoice.find({ buyer: userId }).populate("seller", "name").sort({ updatedAt: -1 }).limit(5)
    ]);

    // Format Data
    const finalTotalPayables = Number((totalPayables[0]?.total || 0).toFixed(2));
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    
    const formattedGraphData = expenseStats.map(item => ({
      name: monthNames[item._id.month - 1],
      expense: Number((item.expense / 1000).toFixed(2)) // K mein convert kiya
    }));

    // --- 3. Live Feed Logic (Recent Orders + Payments) ---
    const paymentEntries = [];
    allInvoicesForFeed.forEach(inv => {
      if (inv.bankStatement && inv.bankStatement.length > 1) {
        inv.bankStatement.slice(1).forEach(entry => {
          if (entry.debit > 0) { // Buyer ke liye Debit matlab payment kiya
            paymentEntries.push({
              id: entry._id,
              name: inv.seller?.name || "Unknown Seller",
              action: "Payment made to seller",
              time: entry.date,
              amount: `-₹${entry.debit.toFixed(2)}`,
              type: "payment"
            });
          }
        });
      }
    });

    const orderEntries = liveFeedOrders.map(o => ({
      id: o._id,
      name: o.items[0]?.seller?.name || "Multiple Sellers",
      action: "Order placed successfully",
      time: o.createdAt,
      amount: `₹${o.total.toFixed(2)}`,
      type: "order"
    }));

    const liveFeed = [...orderEntries, ...paymentEntries]
      .sort((a, b) => new Date(b.time) - new Date(a.time))
      .slice(0, 5); 

    return res.json({
      success: true,
      data: {
        expenseGrowth: Math.round(growthPercentage),
        totalPayables: finalTotalPayables,
        ordersInTransit,
        pendingInvoices: pendingInvoicesCount,
        totalSellers,
        graphData: formattedGraphData,
        liveFeed
      }
    });

  } catch (error) {
    console.error("Buyer Dashboard error:", error);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

// Super Admin Dashboard
export const superAdminDashboard = catchAsyncErrors(async (req, res, next) => {
  try {
    const { days } = req.query;

    const filterDays = parseInt(days) || 7;
    const now = new Date();

    const timeLimit = new Date();
    timeLimit.setDate(timeLimit.getDate() - filterDays);
    timeLimit.setHours(0, 0, 0, 0);

    // =====================================================
    // 1️⃣ USER GROWTH (Seller + Buyer Combined)
    // =====================================================

    const startOfCurrentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0);

    const [currentMonthUsers, lastMonthUsers] = await Promise.all([
      User.countDocuments({
        createdAt: { $gte: startOfCurrentMonth },
        mode: { $in: ["seller", "buyer"] }
      }),
      User.countDocuments({
        createdAt: { $gte: startOfLastMonth, $lte: endOfLastMonth },
        mode: { $in: ["seller", "buyer"] }
      })
    ]);

    let growthPercentage =
      lastMonthUsers > 0
        ? ((currentMonthUsers - lastMonthUsers) / lastMonthUsers) * 100
        : currentMonthUsers > 0
        ? 100
        : 0;

    // =====================================================
    // 2️⃣ MAIN STATS + GRAPH + LIVE DATA
    // =====================================================

    const [
      totalRevenue,
      totalOrders,
      totalSellers,
      totalBuyers,
      totalProducts,
      totalSellerCategories,
      totalBuyerCategories,
      pendingConnections,
      pendingInvoices,
      totalSupportTickets,
      totalContact,
      userStats,
      recentUsers,
      recentContacts,
      recentSupports
    ] = await Promise.all([

      // Revenue
      Order.aggregate([
        { $match: { orderStatus: "Completed", createdAt: { $gte: timeLimit } } },
        { $group: { _id: null, total: { $sum: "$total" } } }
      ]),

      Order.countDocuments({ createdAt: { $gte: timeLimit } }),

      User.countDocuments({ mode: "seller" }),

      User.countDocuments({ mode: "buyer" }),

      Product.countDocuments(),

      SellerCategory.countDocuments(),

      BuyerCategory.countDocuments(),

      BuyerSellerConnection.countDocuments({ status: "Pending" }),

      Invoice.countDocuments({ status: "Pending" }),

      Support.countDocuments(),

      Contact.countDocuments(),

      // 6 Months User Growth Graph
      User.aggregate([
        {
          $match: {
            mode: { $in: ["seller", "buyer"] },
            createdAt: {
              $gte: new Date(new Date().setMonth(now.getMonth() - 6))
            }
          }
        },
        {
          $group: {
            _id: {
              month: { $month: "$createdAt" },
              year: { $year: "$createdAt" }
            },
            totalUsers: { $sum: 1 }
          }
        },
        { $sort: { "_id.year": 1, "_id.month": 1 } }
      ]),

      // Latest 5 Users
      User.find()
        .select("name mode createdAt")
        .sort({ createdAt: -1 })
        .limit(5),

      // Latest 5 Contacts
      Contact.find()
        .select("name message createdAt")
        .sort({ createdAt: -1 })
        .limit(5),

      // Latest 5 Support
      Support.find()
        .populate("user", "name")
        .sort({ createdAt: -1 })
        .limit(5)
    ]);

    const finalRevenue = Number((totalRevenue[0]?.total || 0).toFixed(2));

    // =====================================================
    // 3️⃣ GRAPH FORMATTING
    // =====================================================

    const monthNames = [
      "Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ];

    const formattedGraphData = userStats.map(item => ({
      name: monthNames[item._id.month - 1],
      users: item.totalUsers
    }));

    // =====================================================
    // 4️⃣ LIVE FEED (Users + Contact + Support)
    // =====================================================

    const userFeed = recentUsers.map(user => ({
      id: user._id,
      name: user.name,
      action: `New ${user.mode} registered`,
      time: user.createdAt,
      type: "user",
      // isNew: true
    }));

    const contactFeed = recentContacts.map(contact => ({
      id: contact._id,
      name: contact.name || "Unknown",
      action: contact.message,
      time: contact.createdAt,
      type: "contact"
    }));

    const supportFeed = recentSupports.map(ticket => ({
      id: ticket._id,
      name: ticket.user?.name || "Unknown User",
      action: ticket?.description || "raised a support ticket",
      time: ticket.createdAt,
      type: "support",
      isNew: true
    }));

    const liveFeed = [...userFeed, ...contactFeed, ...supportFeed]
      .sort((a, b) => new Date(b.time) - new Date(a.time))
      .slice(0, 5);

    // =====================================================
    // FINAL RESPONSE
    // =====================================================

    return res.status(200).json({
      success: true,
      data: {
        businessGrowth: Math.round(growthPercentage),
        totalRevenue: finalRevenue,
        totalOrders,
        totalSellers,
        totalBuyers,
        totalProducts,
        totalSellerCategories,
        totalBuyerCategories,
        pendingConnections,
        pendingInvoices,
        totalSupportTickets,
        totalContact,
        graphData: formattedGraphData,
        liveFeed
      }
    });

  } catch (error) {
    console.error("Super Admin Dashboard Error:", error);
    return res.status(500).json({
      success: false,
      message: "Server Error",
      error: error.message
    });
  }
});




