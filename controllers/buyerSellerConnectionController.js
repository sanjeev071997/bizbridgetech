import mongoose from "mongoose";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import User from "../models/userModel.js";
import Plan from "../models/planModel.js";
import Bill from "../models/billModel.js"
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Create Buyer-Seller Connection
// export const createBuyerSellerConnection = catchAsyncErrors(
//   async (req, res, next) => {
//     try {
//       const { buyerPhone, buyerCategory, seller: sellerFromBody } = req.body;

//       if (!buyerPhone || !buyerCategory) {
//         return res.status(400).json({
//           success: false,
//           message: "Buyer phone and category are required",
//         });
//       }

//       const loggedInUserId = req.user._id;

//       const isQRFlow = !!sellerFromBody;
//       const seller = isQRFlow ? sellerFromBody : loggedInUserId;

//       // Check if buyer exists
//       const existingBuyer = await User.findOne({ phone: buyerPhone });

//       const buyerId = existingBuyer ? existingBuyer._id : null;

//       // Prevent self connection
//       if (buyerId && String(seller) === String(buyerId)) {
//         return res.status(400).json({
//           success: false,
//           message: "Seller and Buyer cannot be same user",
//         });
//       }

//       const connection = await BuyerSellerConnection.create({
//         seller,
//         buyer: buyerId, // null if not registered
//         buyerPhone,
//         buyerCategory,
//         status: "Accepted", // direct accepted
//       });

//       if (req.io?.sockets?.sockets?.size > 0) {
//         req.io.emit("newConnection", connection);
//       }

//       res.status(201).json({
//         success: true,
//         message: "Connection saved successfully",
//         data: connection,
//       });
//     } catch (error) {
//       return next(new Errorhandler(error.message, 500));
//     }
//   }
// );

export const createBuyerSellerConnection = catchAsyncErrors(
  async (req, res, next) => {
    try {
      const { buyerPhone, buyerCategory, seller: sellerFromBody } = req.body;

      if (!buyerPhone || !buyerCategory) {
        return res.status(400).json({
          success: false,
          message: "Buyer phone and category are required",
        });
      }

      const loggedInUserId = req.user._id;
      const seller = sellerFromBody ? sellerFromBody : loggedInUserId;

      // 🔹 Step 1: Check if buyer exists in User collection
      let buyer = await User.findOne({ phone: buyerPhone });

      // 🔹 Step 2: If not exist → create buyer
      if (!buyer) {
        buyer = await User.create({
          phone: buyerPhone,
          mode: "buyer",
        });
      }

      const buyerId = buyer._id;

      // 🔹 Prevent self connection
      if (String(seller) === String(buyerId)) {
        return res.status(400).json({
          success: false,
          message: "Seller and Buyer cannot be same user",
        });
      }

      // 🔹 Step 3: Check if connection already exists
      const existingConnection = await BuyerSellerConnection.findOne({
        seller,
        buyer: buyerId,
      });

      if (existingConnection) {
        return res.status(200).json({
          success: true,
          message: "Connection already exists",
          data: existingConnection,
        });
      }

      // 🔹 Step 4: Create connection
      const connection = await BuyerSellerConnection.create({
        seller,
        buyer: buyerId,
        buyerPhone,
        buyerCategory,
        status: "Accepted",
      });

      if (req.io?.sockets?.sockets?.size > 0) {
        req.io.emit("newConnection", connection);
      }

      res.status(201).json({
        success: true,
        message: "Connection saved successfully",
        data: connection,
      });

    } catch (error) {
      return next(new Errorhandler(error.message, 500));
    }
  }
);
// Get Buyer-Seller Connections for logged-in buyer
// export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode; // "buyer" or "seller"

//     // 🔹 Pagination params
//     let page = parseInt(req.query.page) || 1; // default page 1
//     let limit = parseInt(req.query.limit) || 10; // default 10 per page
//     const skip = (page - 1) * limit;

//     let connectionFilter = {};

//     // MODE BASED FILTER
//     if (mode === "buyer") {
//       connectionFilter = { buyer: userId };
//     } else if (mode === "seller") {
//       connectionFilter = { seller: userId };
//     }

//     // Total count for pagination info
//     const totalConnections = await BuyerSellerConnection.countDocuments(connectionFilter);

//     const connections = await BuyerSellerConnection.find(connectionFilter)
//       .populate("buyer", "name email phone businessAddress businessName lastSeen profileImage")
//       .populate("seller", "name email phone businessAddress businessName lastSeen profileImage")
//       .populate("buyerCategory", "name _id discount")
//       .sort({ createdAt: -1 })
//       .skip(skip)
//       .limit(limit);

//     const formattedConnections = connections.map((conn) => {
//       const isBuyer = conn.buyer?._id?.toString() === userId.toString();
//       const otherUser = isBuyer ? conn.seller : conn.buyer;

//       return {
//         _id: conn._id,
//         status: conn.status,
//         buyerCategory: conn.buyerCategory || null,
//         userRole: isBuyer ? "buyer" : "seller",
//         lastSeen: otherUser.lastSeen,
//         otherUser: otherUser
//           ? {
//               _id: otherUser._id,
//               name: otherUser.name,
//               email: otherUser.email,
//               phone: otherUser.phone,
//               businessAddress: otherUser.businessAddress || null,
//               businessName: otherUser.businessName || null,
//               lastSeen: otherUser.lastSeen,
//               profileImage: otherUser.profileImage?.url
//             }
//           : null,
//         createdAt: conn.createdAt,
//         updatedAt: conn.updatedAt,
//       };
//     });

//     res.status(200).json({
//       success: true,
//       page,
//       limit,
//       totalConnections,
//       totalPages: Math.ceil(totalConnections / limit),
//       data: formattedConnections,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });

export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode; // "buyer" or "seller"

    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    let connectionFilter = {};

    // 🔹 Mode based filtering
    if (mode === "buyer") {
      connectionFilter = { buyer: userId };
    } 
    else if (mode === "seller") {
      connectionFilter = { seller: userId };
    }

    const totalConnections = await BuyerSellerConnection.countDocuments(connectionFilter);

    const connections = await BuyerSellerConnection.find(connectionFilter)
      .populate("buyer", "name email phone phoneVerified businessAddress businessName lastSeen profileImage")
      .populate("seller", "name email phone businessAddress businessName lastSeen profileImage")
      .populate("buyerCategory", "name _id discount")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const formattedConnections = connections.map((conn) => {

      const isBuyer = conn.buyer?._id?.toString() === userId.toString();

      let otherUser = null;

      if (mode === "seller") {
        // Seller view
        if (conn.buyer) {
          // Registered buyer
          otherUser = {
            _id: conn.buyer._id,
            name: conn.buyer.name,
            email: conn.buyer.email,
            phone: conn.buyer.phone,
            phoneVerified: conn.buyer.phoneVerified,
            businessAddress: conn.buyer.businessAddress || null,
            businessName: conn.buyer.businessName || null,
            lastSeen: conn.buyer.lastSeen,
            profileImage: conn.buyer.profileImage?.url || null,
            isRegistered: true,
          };
        } else {
          // Unregistered buyer
          otherUser = {
            _id: null,
            name: null,
            email: null,
            phone: conn.buyerPhone,
            phoneVerified:conn.phoneVerified,
            businessAddress: null,
            businessName: null,
            lastSeen: null,
            profileImage: null,
            isRegistered: false,
          };
        }
      } else {
        // Buyer view (always seller will exist)
        otherUser = conn.seller
          ? {
              _id: conn.seller._id,
              name: conn.seller.name,
              email: conn.seller.email,
              phone: conn.seller.phone,
              businessAddress: conn.seller.businessAddress || null,
              businessName: conn.seller.businessName || null,
              lastSeen: conn.seller.lastSeen,
              profileImage: conn.seller.profileImage?.url || null,
            }
          : null;
      }

      return {
        _id: conn._id,
        status: conn.status,
        buyerCategory: conn.buyerCategory || null,
        userRole: mode,
        otherUser,
        createdAt: conn.createdAt,
        updatedAt: conn.updatedAt,
      };
    });

    res.status(200).json({
      success: true,
      page,
      limit,
      totalConnections,
      totalPages: Math.ceil(totalConnections / limit),
      data: formattedConnections,
    });

  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// Get Buyer-Seller Connections based on logged-in user's mode
export const updateConnectionStatus = catchAsyncErrors(
  async (req, res, next) => {
    try {
      const { status } = req.body;
      const connectionId = req.params.id;
      const loggedInUser = req.user._id;

      // Allowed statuses
      if (!["Pending", "Accepted", "Rejected"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid status. Allowed: Pending, Accepted, Rejected",
        });
      }

      // Fetch connection
      const connection = await BuyerSellerConnection.findById(connectionId);

      if (!connection) {
        return next(new Errorhandler("Connection not found", 404));
      }

      const isBuyer = connection.buyer.toString() === loggedInUser.toString();
      const isSeller = connection.seller.toString() === loggedInUser.toString();

      // -----------------------------------------
      // VALIDATION BASED ON RULES
      // -----------------------------------------

      // Only buyer can accept
      if (status === "Accepted" && !isBuyer) {
        return res.status(403).json({
          success: false,
          message: "Only Buyer can accept the connection",
        });
      }

      // Pending can be updated by both
      if (status === "Pending" && !(isBuyer || isSeller)) {
        return res.status(403).json({
          success: false,
          message: "Only Buyer or Seller can set status to Pending",
        });
      }

      // Reject can be done by both
      if (status === "Rejected" && !(isBuyer || isSeller)) {
        return res.status(403).json({
          success: false,
          message: "Only Buyer or Seller can reject the connection",
        });
      }

      // -----------------------------------------
      // UPDATE STATUS
      // -----------------------------------------
      connection.status = status;
      await connection.save();

      // -----------------------------------------
      // EMIT SOCKET EVENT
      // -----------------------------------------
      if (req.io) {
        req.io.emit("connectionStatusUpdated", {
          connectionId,
          status,
          updatedBy: loggedInUser,
        });
      }

      res.status(200).json({
        success: true,
        message: `Connection status updated to ${status}`,
        data: connection,
      });
    } catch (error) {
      return next(new Errorhandler(error.message, 500));
    }
  }
);

// Assigned Category Buyer Seller
export const assignedCategoryBuyerSeller = catchAsyncErrors(
  async (req, res, next) => {
    try {
      const { buyerEmail, buyerPhone, buyerCategory } = req.body;
      const seller = req.user._id;

      if (!buyerEmail && !buyerPhone) {
        return res.status(400).json({
          success: false,
          message: "Either Email or Phone is required",
        });
      }

      if (!buyerCategory) {
        return res.status(400).json({
          success: false,
          message: "Buyer Category is required",
        });
      }

      // Find buyer
      const buyer = await User.findOne({
        $or: [
          buyerEmail ? { email: buyerEmail } : null,
          buyerPhone ? { phone: buyerPhone } : null,
        ].filter(Boolean),
      });

      if (!buyer) {
        return res.status(400).json({
          success: false,
          message: "No user found with given email or phone",
        });
      }

      // Find existing connection
      let connection = await BuyerSellerConnection.findOne({
        seller,
        buyer: buyer._id,
      });

      if (connection) {
        // ✅ Update only category + contact info
        connection.buyerCategory = buyerCategory;
        connection.buyerEmail = buyerEmail || null;
        connection.buyerPhone = buyerPhone || null;

        // ❌ DO NOT auto-accept pending requests
        // status remains as-is (Pending / Accepted)

        await connection.save();
      } else {
        // ✅ New connection → Pending
        connection = await BuyerSellerConnection.create({
          seller,
          buyer: buyer._id,
          buyerEmail: buyerEmail || null,
          buyerPhone: buyerPhone || null,
          buyerCategory,
          status: "Pending",
        });
      }

      // Emit socket event
      if (req.io?.sockets?.sockets?.size > 0) {
        req.io.emit("buyerSellerConnectionUpdated", connection);
      }

      return res.status(200).json({
        success: true,
        message: "Buyer category updated successfully",
        data: connection,
      });
    } catch (error) {
      return next(new Errorhandler(error.message, 500));
    }
  }
);

// View All Members 
export const viewMembers = catchAsyncErrors(async (req, res, next) => {
  try {
    const { buyerCategory, seller, page = 1, limit = 10 } = req.body;

    if (!buyerCategory) {
      return res.status(400).json({
        success: false,
        message: "Buyer Category is required",
      });
    }

    if (!seller) {
      return res.status(400).json({
        success: false,
        message: "Seller is required",
      });
    }

    const pageNumber = Math.max(1, parseInt(page));
    const pageLimit = Math.max(1, Math.min(100, parseInt(limit))); 
    const skip = (pageNumber - 1) * pageLimit;

    const filter = {
      buyerCategory,
      seller,
      status: "Accepted",
    };

    const [members, totalCount] = await Promise.all([
      BuyerSellerConnection.find(filter)
        .populate("buyer", "name email phone profileImage.url")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(pageLimit),

      BuyerSellerConnection.countDocuments(filter),
    ]);

    const totalPages = Math.ceil(totalCount / pageLimit);
    const hasNextPage = pageNumber < totalPages;
    const hasPrevPage = pageNumber > 1;

    return res.status(200).json({
      success: true,
      count: totalCount,
      pagination: {
        total: totalCount,
        page: pageNumber,
        limit: pageLimit,
        totalPages,
        hasNextPage,
        hasPrevPage,
        nextPage: hasNextPage ? pageNumber + 1 : null,
        prevPage: hasPrevPage ? pageNumber - 1 : null,
      },
      data: members,
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// New Apis for Sellers List for a Buyer
// Get all accepted sellers of a buyer
export const sellersList = catchAsyncErrors(async (req, res, next) => {
  const buyer = req.user._id;
  if (!buyer) {
    return next(new Errorhandler("Buyer ID is required", 400));
  }

  if (!mongoose.Types.ObjectId.isValid(buyer)) {
    return next(new Errorhandler("Invalid Buyer ID", 400));
  }

  // Pagination params
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  // Total count (for frontend pagination)
  const totalSellers = await BuyerSellerConnection.countDocuments({
    buyer,
    status: "Accepted",
  });

  // Find paginated data
  const connections = await BuyerSellerConnection.find({
    buyer,
    status: "Accepted",
  })
    .populate(
      "seller",
      "name email phone businessName profileImage.url bankDetails businessAddress"
    )
    .skip(skip)
    .limit(limit)
    .sort({ createdAt: -1 }); // latest first

  res.status(200).json({
    success: true,
    currentPage: page,
    totalPages: Math.ceil(totalSellers / limit),
    totalSellers,
    count: connections.length,
    data: connections,
  });
});


