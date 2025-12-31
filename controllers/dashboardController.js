import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import mongoose from "mongoose";
import Product from "../models/sellerProductModel.js";
import Order from "../models/orderModel.js";
import Invoice from "../models/invoiceModel.js";
import BuyerSellerConnection from '../models/buyerSellerConnectionModels.js';


// export const sellerDashboard = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const { days } = req.query; 
    
//     // Filter logic: Default 7 din
//     const filterDays = parseInt(days) || 7; 
//     const now = new Date();
    
//     // Yaha calculation sahi ki hai:
//     const timeLimit = new Date();
//     timeLimit.setDate(timeLimit.getDate() - filterDays);
//     // Din ki shuruat se filter karne ke liye setHours zaroori hai
//     timeLimit.setHours(0, 0, 0, 0); 

//     // --- 1. Growth Calculation (Current Month vs Last Month) ---
//     const startOfCurrentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
//     const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
//     const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0);

//     const [currentMonthRev, lastMonthRev] = await Promise.all([
//       Order.aggregate([
//         { $match: { "items.seller": userId, orderStatus: "Completed", createdAt: { $gte: startOfCurrentMonth } } },
//         { $group: { _id: null, total: { $sum: "$total" } } }
//       ]),
//       Order.aggregate([
//         { $match: { "items.seller": userId, orderStatus: "Completed", createdAt: { $gte: startOfLastMonth, $lte: endOfLastMonth } } },
//         { $group: { _id: null, total: { $sum: "$total" } } }
//       ])
//     ]);

//     const currentRevValue = currentMonthRev[0]?.total || 0;
//     const lastRevValue = lastMonthRev[0]?.total || 0;
//     let growthPercentage = lastRevValue > 0 ? ((currentRevValue - lastRevValue) / lastRevValue) * 100 : (currentRevValue > 0 ? 100 : 0);

//     // --- 2. Main Stats Data (Filter Fixed) ---
//     const [
//       totalReceivables,
//       ordersInTransit,
//       overdueInvoices,
//       pendingRequests,
//       revenueStats,
//       liveFeedOrders,
//       allInvoicesForFeed
//     ] = await Promise.all([
//       // Receivables: Filtered by days
//       Invoice.aggregate([
//         { $match: { seller: userId, status: "Pending", createdAt: { $gte: timeLimit } } },
//         { $group: { _id: null, total: { $sum: "$amount" } } }
//       ]),

//       // Orders: Filtered by days
//       Order.countDocuments({ 
//         "items.seller": userId, 
//         orderStatus: { $in: ["Processing", "Shipped", "Pending"] },
//         createdAt: { $gte: timeLimit }
//       }),

//       // Overdue: Filtered by days
//       Invoice.countDocuments({ 
//         seller: userId, 
//         status: "Pending", 
//         dueDate: { $lt: new Date() },
//         createdAt: { $gte: timeLimit }
//       }),

//       BuyerSellerConnection.countDocuments({ seller: userId, status: "Pending" }),

//       // Graph: Last 6 months (Hamesha fixed rakhte hain dashboard UI ke liye)
//       Order.aggregate([
//         { $match: { "items.seller": userId, orderStatus: "Completed", createdAt: { $gte: new Date(new Date().setMonth(now.getMonth() - 6)) } } },
//         { $group: { _id: { month: { $month: "$createdAt" }, year: { $year: "$createdAt" } }, revenue: { $sum: "$total" } } },
//         { $sort: { "_id.year": 1, "_id.month": 1 } }
//       ]),

//       Order.find({ "items.seller": userId }).populate("buyer", "name").sort({ createdAt: -1 }).limit(5),
//       Invoice.find({ seller: userId }).populate("buyer", "name").sort({ updatedAt: -1 }).limit(5)
//     ]);

//     // --- 3. Live Feed Logic (Index 0 skip) ---
//     const paymentEntries = [];
//     allInvoicesForFeed.forEach(inv => {
//       if (inv.bankStatement && inv.bankStatement.length > 1) {
//         // First entry skip karke baki credit entries uthayenge
//         inv.bankStatement.slice(1).forEach(entry => {
//           if (entry.credit > 0) {
//             paymentEntries.push({
//               id: entry._id,
//               name: inv.buyer?.name || "Unknown Buyer",
//               action: entry.description || "received a payment.",
//               time: entry.date,
//               amount: `+₹${entry.credit.toLocaleString()}`,
//               type: "payment"
//             });
//           }
//         });
//       }
//     });

//     const orderEntries = liveFeedOrders.map(o => ({
//       id: o._id,
//       name: o.buyer?.name || "Unknown Buyer",
//       action: "placed an order.",
//       time: o.createdAt,
//       amount: `₹${o.total.toLocaleString()}`,
//       type: "order"
//     }));

//     // Top 5 overall merge
//     const liveFeed = [...orderEntries, ...paymentEntries]
//       .sort((a, b) => new Date(b.time) - new Date(a.time))
//       .slice(0, 5); 

//     const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
//     const formattedGraphData = revenueStats.map(item => ({
//       name: monthNames[item._id.month - 1],
//       revenue: item.revenue / 1000 
//     }));

//     return res.json({
//       success: true,
//       data: {
//         businessGrowth: Math.round(growthPercentage),
//         totalReceivables: totalReceivables[0]?.total || 0,
//         ordersInTransit,
//         overdueInvoices,
//         pendingRequests,
//         graphData: formattedGraphData,
//         liveFeed
//       }
//     });

//   } catch (error) {
//     console.error("Dashboard stats error:", error);
//     return res.status(500).json({ success: false, message: "Server error", error: error.message });
//   }
// });


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

export const buyerDashboard = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode;

    // 🔐 Buyer mode check
    if (mode !== "buyer") {
      return res.status(403).json({
        success: false,
        message: "Access denied. Buyer mode required.",
      });
    }

    const [
      pendingOrders,
      pendingInvoicesCount,
      totalSeller,
      top5Sellers,
    ] = await Promise.all([
      // Pending orders
      Order.countDocuments({ buyer: userId, orderStatus: "Pending" }),

      // Pending invoices
      Invoice.countDocuments({ buyer: userId, status: "Pending" }),

      // Total connected sellers
      BuyerSellerConnection.countDocuments({ buyer: userId }),

      // 🔥 Top 5 sellers (Completed orders)
      Order.aggregate([
        {
          $match: {
            buyer: userId,
            orderStatus: "Completed",
          },
        },
        { $unwind: "$items" },
        {
          $group: {
            _id: "$items.seller",
            totalOrders: { $sum: 1 },
            totalQuantity: { $sum: "$items.quantity" },
            totalAmount: { $sum: "$items.finalPrice" },
          },
        },
        { $sort: { totalAmount: -1 } },
        { $limit: 5 },
        {
          $lookup: {
            from: "users", // ⚠️ seller collection name
            localField: "_id",
            foreignField: "_id",
            as: "seller",
          },
        },
        { $unwind: "$seller" },
        {
          $project: {
            _id: 0,
            sellerId: "$seller._id",
            sellerName: "$seller.name",
            sellerEmail: "$seller.email",
            totalOrders: 1,
            totalQuantity: 1,
            totalAmount: 1,
          },
        },
      ]),
    ]);

    return res.json({
      success: true,
      data: {
        pendingOrders,
        pendingInvoices: pendingInvoicesCount,
        totalSeller,
        top5Sellers, // ✅ NEW DATA
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
});
