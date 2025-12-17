import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import User from "../models/userModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Create Buyer-Seller Connection
export const createBuyerSellerConnection = catchAsyncErrors(
  async (req, res, next) => {
    try {
      const { buyerEmail, buyerPhone, buyerCategory } = req.body;
      const seller = req.user._id; // Logged in user is seller

     // Validation: at least one field required
      if (!buyerEmail && !buyerPhone) {
        return res
          .status(400)
          .json({ success: false, message: "Either Email or Phone is required" });
      }

    if (!buyerCategory) {
        return res
          .status(400)
          .json({ success: false, message: "Buyer Category is required" });
      }

      // Find buyer by email or phone (whichever exists)
      const buyer = await User.findOne({
        $or: [
          buyerEmail ? { email: buyerEmail } : null,
          buyerPhone ? { phone: buyerPhone } : null
        ].filter(Boolean), // remove null conditions
      });

         // Check if found user has at least one of email or phone
      if (!buyer) {
        return res.status(400).json({
          success: false,
          message: "No user found with the given email or phone",
        });
      }

      const connection = await BuyerSellerConnection.create({
        seller,
        buyer: buyer?._id || null, // Save buyer id if found
        buyerEmail: buyerEmail || null,
        buyerPhone: buyerPhone || null,
        buyerCategory,
      });

        // Emit to Socket.IO
      const connectedSockets = req.io.sockets.sockets.size;
      if (connectedSockets > 0) {
        req.io.emit("newConnection", connection);
        console.log(`Event sent to ${connectedSockets} clients`);
      } else {
        console.warn("No clients connected to receive the event");
      }

      res.status(201).json({
        success: true,
        message: "Connection created successfully",
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

//     // Find all connections where user is buyer or seller
//     const connectionFilter = {
//       $or: [{ buyer: userId }, { seller: userId }],
//     };

//     const connections = await BuyerSellerConnection.find(connectionFilter)
//       .populate("buyer", "name email phone businessAddress")
//       .populate("seller", "name email phone businessAddress")
//       .populate("buyerCategory", "name _id discount")
//       .sort({ createdAt: -1 });

//     if (!connections.length) {
//       return res.status(200).json({
//         success: true,
//         data: [],
//       });
//     }

//     // Format safely (check for null buyer/seller)
//     const formattedConnections = connections
//       .filter((conn) => conn.buyer && conn.seller) 
//       .map((conn) => {
//         const isBuyer =
//           conn.buyer?._id?.toString() === userId.toString() ? true : false;
//         const otherUser = isBuyer ? conn.seller : conn.buyer;

//         return {
//           _id: conn._id,
//           status: conn.status,
//           buyerCategory:
//             conn.buyerCategory?._id ||
//             conn.buyerCategory?.name ||
//             conn.buyerCategory?.discount ||
//             null,
//           userRole: isBuyer ? "buyer" : "seller",
//           otherUser: otherUser
//             ? {
//                 _id: otherUser._id,
//                 name: otherUser.name,
//                 email: otherUser.email,
//                 phone: otherUser.phone,
//                 businessAddress: otherUser.businessAddress || null,
//               }
//             : null,
//           createdAt: conn.createdAt,
//           updatedAt: conn.updatedAt,
//         };
//       });

//     res.status(200).json({
//       success: true,
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

    let connectionFilter = {};

    // MODE BASED FILTER
    if (mode === "buyer") {
      // Buyer mode → Only received requests (seller sent)
      connectionFilter = { buyer: userId };
    } else if (mode === "seller") {
      // Seller mode → Only requests sent by seller
      connectionFilter = { seller: userId };
    }

    const connections = await BuyerSellerConnection.find(connectionFilter)
      .populate("buyer", "name email phone businessAddress businessName")
      .populate("seller", "name email phone businessAddress businessName")
      .populate("buyerCategory", "name _id discount")
      .sort({ createdAt: -1 });

    const formattedConnections = connections.map((conn) => {
      const isBuyer = conn.buyer?._id?.toString() === userId.toString();
      const otherUser = isBuyer ? conn.seller : conn.buyer;

      return {
        _id: conn._id,
        status: conn.status,
        buyerCategory: conn.buyerCategory || null,
        userRole: isBuyer ? "buyer" : "seller",
        otherUser: otherUser ? {
          _id: otherUser._id,
          name: otherUser.name,
          email: otherUser.email,
          phone: otherUser.phone,
          businessAddress: otherUser.businessAddress || null,
          businessName: otherUser.businessName || null,
        } : null,
        createdAt: conn.createdAt,
        updatedAt: conn.updatedAt,
      };
    });

    res.status(200).json({
      success: true,
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

// Get All Buyer-Seller Connections (Admin Only)
// export const getAllBuyerSellerConnections = catchAsyncErrors(
//   async (req, res, next) => {
//     try {
//       const connections = await BuyerSellerConnection.find()
//         .populate("seller", "name email")
//         .populate("buyer", "name email")
//         .populate("buyerCategory", "name");

//       return res.status(200).json({
//         success: true,
//         message: "All connections retrieved",
//         data: connections,
//       });
//     } catch (error) {
//       return next(new Errorhandler(error.message, 500));
//     }
//   }
// );
