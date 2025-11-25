import Contact from "../models/contactModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import mongoose from "mongoose";
import Product from "../models/sellerProductModel.js";
import Order from "../models/orderModel.js";
import Invoice from "../models/invoiceModel.js";


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

      // 🟢 Latest 5 Orders
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
