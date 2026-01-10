import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import User from "../models/userModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Create Buyer-Seller Connection
// export const createBuyerSellerConnection = catchAsyncErrors(
//   async (req, res, next) => {
//     try {
//       const { buyerEmail, buyerPhone, buyerCategory } = req.body;
//       const seller = req.user._id; // Logged in user is seller

//      // Validation: at least one field required
//       if (!buyerEmail && !buyerPhone) {
//         return res
//           .status(400)
//           .json({ success: false, message: "Either Email or Phone is required" });
//       }

//     if (!buyerCategory) {
//         return res
//           .status(400)
//           .json({ success: false, message: "Buyer Category is required" });
//       }

//       // Find buyer by email or phone (whichever exists)
//       const buyer = await User.findOne({
//         $or: [
//           buyerEmail ? { email: buyerEmail } : null,
//           buyerPhone ? { phone: buyerPhone } : null
//         ].filter(Boolean), // remove null conditions
//       });

//          // Check if found user has at least one of email or phone
//       if (!buyer) {
//         return res.status(400).json({
//           success: false,
//           message: "No user found with the given email or phone",
//         });
//       }

//       const connection = await BuyerSellerConnection.create({
//         seller,
//         buyer: buyer?._id || null, // Save buyer id if found
//         buyerEmail: buyerEmail || null,
//         buyerPhone: buyerPhone || null,
//         buyerCategory,
//       });

//         // Emit to Socket.IO
//       const connectedSockets = req.io.sockets.sockets.size;
//       if (connectedSockets > 0) {
//         req.io.emit("newConnection", connection);
//         console.log(`Event sent to ${connectedSockets} clients`);
//       } else {
//         console.warn("No clients connected to receive the event");
//       }

//       res.status(201).json({
//         success: true,
//         message: "Connection created successfully",
//         data: connection,
//       });
//     } catch (error) {
//       return next(new Errorhandler(error.message, 500));
//     }
//   }
// );


// export const createBuyerSellerConnection = catchAsyncErrors(
//   async (req, res, next) => {
//     try {
//       const { buyerEmail, buyerPhone, buyerCategory } = req.body;
//       const seller = req.user._id; // Logged in user is seller

//       // Validation: at least one field required
//       if (!buyerEmail && !buyerPhone) {
//         return res
//           .status(400)
//           .json({ success: false, message: "Either Email or Phone is required" });
//       }

//       if (!buyerCategory) {
//         return res
//           .status(400)
//           .json({ success: false, message: "Buyer Category is required" });
//       }

//       // Find buyer
//       const buyer = await User.findOne({
//         $or: [
//           buyerEmail ? { email: buyerEmail } : null,
//           buyerPhone ? { phone: buyerPhone } : null,
//         ].filter(Boolean),
//       });

//       if (!buyer) {
//         return res.status(400).json({
//           success: false,
//           message: "No user found with the given email or phone",
//         });
//       }

//       // Check if a connection already exists for this seller-buyer
//    // Find existing connection as Mongoose document
// let existingConnection = await BuyerSellerConnection.findOne({
//   seller,
//   buyer: buyer._id,
// }).exec(); // <-- ensure Mongoose doc

// // Case 1: Already Accepted → replace old Accepted with new one
// if (existingConnection && existingConnection.status === "Accepted") {
//   // Remove old Accepted
//   await BuyerSellerConnection.deleteOne({ _id: existingConnection._id });

//   // Create new Pending connection
//   const newConnection = await BuyerSellerConnection.create({
//     seller,
//     buyer: buyer._id,
//     buyerEmail: buyerEmail || null,
//     buyerPhone: buyerPhone || null,
//     buyerCategory,
//     status: "Pending",
//   });

//   return res.status(201).json({
//     success: true,
//     message:
//       "Previous accepted connection replaced with new pending request",
//     data: newConnection,
//   });
// }

// // Case 2: Pending exists → update category only
// if (existingConnection && existingConnection.status === "Pending") {
//   existingConnection.buyerCategory = buyerCategory;
//   await existingConnection.save(); // ✅ this works now

//   return res.status(200).json({
//     success: true,
//     message: "Pending request updated with new category",
//     data: existingConnection,
//   });
// }


//       // Case 2: Pending exists → update category only
//       if (existingConnection && existingConnection.status === "Pending") {
//         existingConnection.buyerCategory = buyerCategory;
//         await existingConnection.save();

//         return res.status(200).json({
//           success: true,
//           message: "Pending request updated with new category",
//           data: existingConnection,
//         });
//       }

//       // Case 3: No existing connection → create new
//       const connection = await BuyerSellerConnection.create({
//         seller,
//         buyer: buyer._id,
//         buyerEmail: buyerEmail || null,
//         buyerPhone: buyerPhone || null,
//         buyerCategory,
//         status: "Pending", // new connection always starts as Pending
//       });

//       // Emit to Socket.IO
//       const connectedSockets = req.io.sockets.sockets.size;
//       if (connectedSockets > 0) {
//         req.io.emit("newConnection", connection);
//         console.log(`Event sent to ${connectedSockets} clients`);
//       } else {
//         console.warn("No clients connected to receive the event");
//       }

//       res.status(201).json({
//         success: true,
//         message: "Connection created successfully",
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
      const { buyerEmail, buyerPhone, buyerCategory } = req.body;
      const seller = req.user._id;

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

      const buyer = await User.findOne({
        $or: [
          buyerEmail ? { email: buyerEmail } : null,
          buyerPhone ? { phone: buyerPhone } : null,
        ].filter(Boolean),
      });

      if (!buyer) {
        return res.status(400).json({
          success: false,
          message: "No user found with the given email or phone",
        });
      }

      let existingConnection = await BuyerSellerConnection.findOne({
        seller,
        buyer: buyer._id,
      }).exec();

      let connection;
      let message;

      // Case 1: Already Accepted → replace old Accepted with new Pending
      if (existingConnection && existingConnection.status === "Accepted") {
        await BuyerSellerConnection.deleteOne({ _id: existingConnection._id });

        connection = await BuyerSellerConnection.create({
          seller,
          buyer: buyer._id,
          buyerEmail: buyerEmail || null,
          buyerPhone: buyerPhone || null,
          buyerCategory,
          status: "Pending",
        });

        message = "Previous accepted connection replaced with new pending request";
      }
      // Case 2: Pending exists → update category only
      else if (existingConnection && existingConnection.status === "Pending") {
        existingConnection.buyerCategory = buyerCategory;
        await existingConnection.save();
        connection = existingConnection;
        message = "Pending request updated with new category";
      }
      // Case 3: No existing connection → create new
      else {
        connection = await BuyerSellerConnection.create({
          seller,
          buyer: buyer._id,
          buyerEmail: buyerEmail || null,
          buyerPhone: buyerPhone || null,
          buyerCategory,
          status: "Pending",
        });
        message = "Connection created successfully";
      }

      // Emit to Socket.IO in all cases
      const connectedSockets = req.io.sockets.sockets.size;
      if (connectedSockets > 0) {
        req.io.emit("newConnection", connection);
        console.log(`Event sent to ${connectedSockets} clients`);
      } else {
        console.warn("No clients connected to receive the event");
      }

      res.status(201).json({
        success: true,
        message,
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

//     let connectionFilter = {};

//     // MODE BASED FILTER
//     if (mode === "buyer") {
//       // Buyer mode → Only received requests (seller sent)
//       connectionFilter = { buyer: userId };
//     } else if (mode === "seller") {
//       // Seller mode → Only requests sent by seller
//       connectionFilter = { seller: userId };
//     }

//     const connections = await BuyerSellerConnection.find(connectionFilter)
//       .populate("buyer", "name email phone businessAddress businessName")
//       .populate("seller", "name email phone businessAddress businessName")
//       .populate("buyerCategory", "name _id discount")
//       .sort({ createdAt: -1 });

//     const formattedConnections = connections.map((conn) => {
//       const isBuyer = conn.buyer?._id?.toString() === userId.toString();
//       const otherUser = isBuyer ? conn.seller : conn.buyer;

//       return {
//         _id: conn._id,
//         status: conn.status,
//         buyerCategory: conn.buyerCategory || null,
//         userRole: isBuyer ? "buyer" : "seller",
//         otherUser: otherUser ? {
//           _id: otherUser._id,
//           name: otherUser.name,
//           email: otherUser.email,
//           phone: otherUser.phone,
//           businessAddress: otherUser.businessAddress || null,
//           businessName: otherUser.businessName || null,
//         } : null,
//         createdAt: conn.createdAt,
//         updatedAt: conn.updatedAt,
//       };
//     });

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

    // 🔹 Pagination params
    let page = parseInt(req.query.page) || 1; // default page 1
    let limit = parseInt(req.query.limit) || 10; // default 10 per page
    const skip = (page - 1) * limit;

    let connectionFilter = {};

    // MODE BASED FILTER
    if (mode === "buyer") {
      connectionFilter = { buyer: userId };
    } else if (mode === "seller") {
      connectionFilter = { seller: userId };
    }

    // Total count for pagination info
    const totalConnections = await BuyerSellerConnection.countDocuments(connectionFilter);

    const connections = await BuyerSellerConnection.find(connectionFilter)
      .populate("buyer", "name email phone businessAddress businessName lastSeen ProfileImage")
      .populate("seller", "name email phone businessAddress businessName lastSeen ProfileImage")
      .populate("buyerCategory", "name _id discount")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const formattedConnections = connections.map((conn) => {
      const isBuyer = conn.buyer?._id?.toString() === userId.toString();
      const otherUser = isBuyer ? conn.seller : conn.buyer;

      return {
        _id: conn._id,
        status: conn.status,
        buyerCategory: conn.buyerCategory || null,
        userRole: isBuyer ? "buyer" : "seller",
        lastSeen: otherUser.lastSeen,
        otherUser: otherUser
          ? {
              _id: otherUser._id,
              name: otherUser.name,
              email: otherUser.email,
              phone: otherUser.phone,
              businessAddress: otherUser.businessAddress || null,
              businessName: otherUser.businessName || null,
              lastSeen: otherUser.lastSeen,
              profileImage: otherUser.ProfileImage?.url
            }
          : null,
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

// Assigned Category Buyer Seller
// export const assignedCategoryBuyerSeller = catchAsyncErrors(
//   async (req, res, next) => {
//     try {
//       const { buyerEmail, buyerPhone, buyerCategory } = req.body;
//       const seller = req.user._id;

//       if (!buyerEmail && !buyerPhone) {
//         return res.status(400).json({
//           success: false,
//           message: "Either Email or Phone is required",
//         });
//       }

//       if (!buyerCategory) {
//         return res.status(400).json({
//           success: false,
//           message: "Buyer Category is required",
//         });
//       }

//       // Find buyer
//       const buyer = await User.findOne({
//         $or: [
//           buyerEmail ? { email: buyerEmail } : null,
//           buyerPhone ? { phone: buyerPhone } : null,
//         ].filter(Boolean),
//       });

//       if (!buyer) {
//         return res.status(400).json({
//           success: false,
//           message: "No user found with given email or phone",
//         });
//       }

//       // Check existing connection
//       let connection = await BuyerSellerConnection.findOne({
//         seller,
//         buyer: buyer._id,
//       });

//       // If exists → UPDATE
//       if (connection) {
//         connection.buyerCategory = buyerCategory;
//         connection.buyerEmail = buyerEmail || null;
//         connection.buyerPhone = buyerPhone || null;
//         connection.status = "Accepted"; 
//         await connection.save();
//       }
//       else {
//         connection = await BuyerSellerConnection.create({
//           seller,
//           buyer: buyer._id,
//           buyerEmail: buyerEmail || null,
//           buyerPhone: buyerPhone || null,
//           buyerCategory,
//           status: "Accepted",
//         });
//       }

//       // Emit socket event
//       if (req.io?.sockets?.sockets?.size > 0) {
//         req.io.emit("buyerSellerConnectionUpdated", connection);
//       }

//       return res.status(201).json({
//         success: true,
//         message: "Buyer–Seller assigned category saved successfully",
//         data: connection,
//       });
//     } catch (error) {
//       return next(new Errorhandler(error.message, 500));
//     }
//   }
// );

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
// export const viewMembers = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const { buyerCategory, seller } = req.body;

//     if (!buyerCategory) {
//       return res.status(400).json({
//         success: false,
//         message: "Buyer Category is required",
//       });
//     }

//     if (!seller) {
//       return res.status(400).json({
//         success: false,
//         message: "Seller is required",
//       });
//     }

//     const allViewMembers = await BuyerSellerConnection.find({
//       buyerCategory: buyerCategory,
//       seller: seller,
//       status: "Accepted", // optional (agar sirf accepted buyers chahiye)
//     })
//       .populate("buyer", "name email phone") // optional
//       .sort({ createdAt: -1 });

//     return res.status(200).json({
//       success: true,
//       count: allViewMembers.length,
//       data: allViewMembers,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });

// export const viewMembers = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const { buyerCategory, seller } = req.body;

//     if (!buyerCategory) {
//       return res.status(400).json({
//         success: false,
//         message: "Buyer Category is required",
//       });
//     }

//     if (!seller) {
//       return res.status(400).json({
//         success: false,
//         message: "Seller is required",
//       });
//     }

//     const filter = {
//       buyerCategory,
//       seller,
//       status: "Accepted", // optional
//     };

//     // 🔥 Parallel queries (fast)
//     const [members, totalCount] = await Promise.all([
//       BuyerSellerConnection.find(filter)
//         .populate("buyer", "name email phone")
//         .sort({ createdAt: -1 }),

//       BuyerSellerConnection.countDocuments(filter),
//     ]);

//     return res.status(200).json({
//       success: true,
//       count: totalCount,
//       data: members,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });


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
        .populate("buyer", "name email phone ProfileImage.url")
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
