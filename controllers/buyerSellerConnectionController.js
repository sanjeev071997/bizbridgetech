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
// export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
//   try {
//     // const buyer = req.user._id;
//     const seller = req.user._id;
//     const buyer = req.user._id;

//     // Fetch connections where the logged-in user is the buyer

 
//     const connections = await BuyerSellerConnection.find({
//       // seller: seller,
//       buyer: buyer,
//     })
//      .populate("seller", "name email phone businessAddress") // seller ka data
//       .populate("buyer", "name email phone businessAddress") // buyer ka data
//       .populate("buyerCategory", "name") // category ka data
//         .sort({ createdAt: -1 }); // latest first

//     //  const mode = req.user.mode; // 'buyer' or 'seller'

//     // let query = {};

//     // if (mode === "buyer") {
//     //   query = { buyer: userId }; // buyer ke connections
//     // } else if (mode === "seller") {
//     //   query = { seller: userId }; // seller ke connections
//     // } else {
//     //   return res.status(400).json({
//     //     success: false,
//     //     message: "Invalid user mode",
//     //   });
//     // }

//     // const connections = await BuyerSellerConnection.find(query)
//     //   .populate("seller", "name email phone businessAddress") // seller info
//     //   .populate("buyer", "name email phone businessAddress") // buyer info
//     //   .populate("buyerCategory", "name") // category info
//     //   .sort({ createdAt: -1 }); 

//     res.status(200).json({
//       success: true,
//       data: connections,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });

// Get Buyer-Seller Connections for logged-in user (buyer or seller)
// export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode; // "buyer" or "seller"

//     console.log("User IDss:", userId);
//     console.log("Mode:", mode);

//     // Build filter — user can be either buyer or seller
//     const connectionFilter = {
//       $or: [{ buyer: userId }, { seller: userId }],
//     };

//     console.log("Connection Filter:", JSON.stringify(connectionFilter, null, 2));

//     // Find all connections where user is buyer or seller
//     const connections = await BuyerSellerConnection.find(connectionFilter)
//       .populate("buyer", "name email phone businessAddress")
//       .populate("seller", "name email phone businessAddress")
//       .populate("buyerCategory", "name")
//       .sort({ createdAt: -1 });

//     console.log("Found Connections:", connections.length);

//     if (connections.length === 0) {
//       return res.status(200).json({
//         success: true,
//         data: [],
//       });
//     }

//     // Format the connections for clear response (optional cleanup)
//     const formattedConnections = connections.map((conn) => {
//       const isBuyer = conn.buyer._id.toString() === userId.toString();
//       const otherUser = isBuyer ? conn.seller : conn.buyer;

//       return {
//         _id: conn._id,
//         status: conn.status,
//         buyerCategory: conn.buyerCategory?.name || null,
//         userRole: isBuyer ? "buyer" : "seller",
//         otherUser: {
//           _id: otherUser._id,
//           name: otherUser.name,
//           email: otherUser.email,
//           phone: otherUser.phone,
//           businessAddress: otherUser.businessAddress || null,
//         },
//         createdAt: conn.createdAt,
//         updatedAt: conn.updatedAt,
//       };
//     });

//     res.status(200).json({
//       success: true,
//       data: formattedConnections,
//     });
//   } catch (error) {
//     console.error("Error in getBuyerConnections:", error);
//     return next(new Errorhandler(error.message, 500));
//   }
// });

export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode; // "buyer" or "seller"

    console.log("User ID:", userId);
    console.log("Mode:", mode);

    // Find all connections where user is buyer or seller
    const connectionFilter = {
      $or: [{ buyer: userId }, { seller: userId }],
    };

    console.log("Connection Filter:", JSON.stringify(connectionFilter, null, 2));

    const connections = await BuyerSellerConnection.find(connectionFilter)
      .populate("buyer", "name email phone businessAddress")
      .populate("seller", "name email phone businessAddress")
      .populate("buyerCategory", "name")
      .sort({ createdAt: -1 });

    console.log("Found Connections:", connections.length);

    if (!connections.length) {
      return res.status(200).json({
        success: true,
        data: [],
      });
    }

    // Format safely (check for null buyer/seller)
    const formattedConnections = connections
      .filter((conn) => conn.buyer && conn.seller) // 👈 Skip broken connections
      .map((conn) => {
        const isBuyer =
          conn.buyer?._id?.toString() === userId.toString() ? true : false;
        const otherUser = isBuyer ? conn.seller : conn.buyer;

        return {
          _id: conn._id,
          status: conn.status,
          buyerCategory: conn.buyerCategory?.name || null,
          userRole: isBuyer ? "buyer" : "seller",
          otherUser: otherUser
            ? {
                _id: otherUser._id,
                name: otherUser.name,
                email: otherUser.email,
                phone: otherUser.phone,
                businessAddress: otherUser.businessAddress || null,
              }
            : null,
          createdAt: conn.createdAt,
          updatedAt: conn.updatedAt,
        };
      });

    res.status(200).json({
      success: true,
      data: formattedConnections,
    });
  } catch (error) {
    console.error("Error in getBuyerConnections:", error);
    return next(new Errorhandler(error.message, 500));
  }
});



// Get Buyer-Seller Connections based on logged-in user's mode
// export const getBuyerConnections = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode; // 'buyer' or 'seller'

//     let query = {};

//     if (mode === "buyer") {
//       query = { buyer: userId }; // buyer ke connections
//     } else if (mode === "seller") {
//       query = { seller: userId }; // seller ke connections
//     } else {
//       return res.status(400).json({
//         success: false,
//         message: "Invalid user mode",
//       });
//     }

//     const connections = await BuyerSellerConnection.find(query)
//       .populate("seller", "name email phone businessAddress") // seller info
//       .populate("buyer", "name email phone businessAddress") // buyer info
//       .populate("buyerCategory", "name") // category info
//       .sort({ createdAt: -1 }); // latest first

//     res.status(200).json({
//       success: true,
//       data: connections,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });


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