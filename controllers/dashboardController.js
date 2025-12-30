import Contact from "../models/contactModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import mongoose from "mongoose";
import Product from "../models/sellerProductModel.js";
import Order from "../models/orderModel.js";
import Invoice from "../models/invoiceModel.js";
import BuyerSellerConnection from '../models/buyerSellerConnectionModels.js';


// export const sellerDashboard = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id; // logged-in seller

//     const [
//       totalProducts,
//       totalOrders,
//       pendingInvoicesCount
//     ] = await Promise.all([
//       // 🟢 Count products of this seller
//       Product.countDocuments({ user: userId }),

//       // 🟢 Count orders where this seller is in items array
//       Order.countDocuments({ "items.seller": userId }),

//       // 🟢 Count pending invoices for this seller
//       Invoice.countDocuments({ seller: userId, status: "Pending" }),
//     ]);

//     return res.json({
//       success: true,
//       data: {
//         totalProducts,
//         totalOrders,
//         pendingInvoices: pendingInvoicesCount,
//       }
//     });

//   } catch (error) {
//     console.error("Dashboard stats error:", error);
//     return res.status(500).json({
//       success: false,
//       message: "Server error",
//       error: error.message,
//     });
//   }
// });



export const sellerDashboard = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;

    const [
      totalProducts,
      totalOrders,
      pendingInvoicesCount,
      recentOrders,
      recentInvoices
    ] = await Promise.all([
      Product.countDocuments({ user: userId }),
      Order.countDocuments({ "items.seller": userId }),
      Invoice.countDocuments({ seller: userId, status: "Pending" }),

      // Latest 5 Orders
      Order.find({ "items.seller": userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .select("orderNumber totalAmount status createdAt"),

      // 🟢 Latest 5 Invoices
      Invoice.find({ seller: userId, status: "Pending" })
        .sort({ createdAt: -1 })
        .limit(5)
        .select("invoiceNumber amount status createdAt")
    ]);

    return res.json({
      success: true,
      data: {
        totalProducts,
        totalOrders,
        pendingInvoices: pendingInvoicesCount,
        recentOrders,
        recentInvoices
      }
    });

  } catch (error) {
    console.error("Dashboard stats error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
});

// export const buyerDashboard = catchAsyncErrors(async (req, res, next) => {
//    try {
//   const userId = req.user._id;

//   const mode = req.user.mode;

//   if (mode !== "buyer") {
//       return res.status(403).json({
//         success: false,
//         message: "Access denied. Buyer mode required.",
//       });
//     }

//   const [
//       pendingOrders,
//       pendingInvoicesCount,
//       totalSeller,
//     ] = await Promise.all([
//       Order.countDocuments({ buyer: userId, orderStatus: "Pending" }),
//       Invoice.countDocuments({ buyer: userId, status: "Pending" }),
//       BuyerSellerConnection.countDocuments({ buyer: userId,})
//     ]);

//      return res.json({
//       success: true,
//       data: {
//         pendingOrders,
//         pendingInvoices: pendingInvoicesCount,
//         totalSeller
//       }
//     });

//   } catch (error) {
//     return res.status(500).json({
//       success: false,
//       message: "Server error",
//       error: error.message,
//     });
//   }
// })


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
