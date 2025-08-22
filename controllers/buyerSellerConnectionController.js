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

    //   // Find buyer by email or phone
    //   const buyer = await User.findOne({
    //     $or: [{ email: buyerEmail }, { phone: buyerPhone }],
    //   });

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
export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
  try {
    const buyer = req.user._id;
 
    const connections = await BuyerSellerConnection.find({
      buyer: buyer,
    })
     .populate("seller", "name email phone") // seller ka data
      .populate("buyer", "name email phone") // buyer ka data
      .populate("buyerCategory", "name") // category ka data
        .sort({ createdAt: -1 }); // latest first

    res.status(200).json({
      success: true,
      data: connections,
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});


export const updateConnectionStatus = catchAsyncErrors(async (req, res, next) => {
  try {
    const { status } = req.body;
    const connectionId = req.params.id;
    const buyerId = req.user._id; // Logged-in buyer

    // Validation
    if (!["Accepted", "Rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid status. Allowed: Accepted, Rejected",
      });
    }

    // Find the connection and ensure buyer is the one updating
    const connection = await BuyerSellerConnection.findOne({
      _id: connectionId,
      buyer: buyerId,
    });

    if (!connection) {
      return next(new Errorhandler("Connection not found or not authorized", 404));
    }

    // Update status
    connection.status = status;
    await connection.save();

    // Emit real-time event
    if (req.io) {
      req.io.emit("connectionStatusUpdated", {
        connectionId,
        status,
        updatedBy: buyerId,
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
});



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