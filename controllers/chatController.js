import ChatMessage from "../models/Chat.js";
import User from "../models/userModel.js"
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import mongoose from "mongoose";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";

// Send message (store in DB + emit via Socket.IO)
export const sendMessage = catchAsyncErrors(async (req, res, next) => {
  try {
    const { receiverId, message } = req.body;
    const senderId = req.user._id;

    if (!receiverId || !message) {
      return res.status(400).json({ 
        success: false, 
        message: "Receiver and message are required" 
      });
    }

    const receiver = await User.findById(receiverId);

    if (!receiver) {
      console.error("sendMessage: Receiver not found:", receiverId);
      return res.status(404).json({ 
        success: false, 
        message: "Receiver not found" 
      });
    }

    const chat = await ChatMessage.create({
      sender: senderId,
      receiver: receiverId,
      message,
      createdAt: new Date().toISOString(),
      isRead: false,
    });

    const populatedChat = await ChatMessage.findById(chat._id)
      .populate("sender", "name email phone")
      .populate("receiver", "name email phone");
    
    if (req.io) {
      console.log("Emitting receiveMessage to:", {
        sender: senderId.toString(),
        receiver: receiverId.toString()
      });
      
      req.io.to(senderId.toString()).emit("receiveMessage", populatedChat);
      req.io.to(receiverId.toString()).emit("receiveMessage", populatedChat);
      
    } else {
      console.error("req.io is not available");
    }

    res.status(201).json({
      success: true,
      message: "Message sent successfully",
      data: populatedChat,
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// Get list of users the authenticated user has chatted with
// export const getChatList = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const chats = await ChatMessage.aggregate([
//       {
//         $match: {
//           $or: [{ sender: userId }, { receiver: userId }],
//         },
//       },
//       {
//         $sort: { createdAt: -1 },
//       },
//       {
//         $group: {
//           _id: {
//             $cond: [
//               { $eq: ["$sender", userId] },
//               "$receiver",
//               "$sender",
//             ],
//           },
//           lastMessage: { $first: "$message" },
//           time: { $first: "$createdAt" },
//           unreadCount: {
//             $sum: {
//               $cond: [
//                 { $and: [{ $eq: ["$receiver", userId] }, { $eq: ["$isRead", false] }] },
//                 1,
//                 0,
//               ],
//             },
//           },
//         },
//       },
//       {
//         $lookup: {
//           from: "users",
//           localField: "_id",
//           foreignField: "_id",
//           as: "user",
//         },
//       },
//       { $unwind: "$user" },
//       {
//         $project: {
//           _id: 1,
//           name: "$user.name",
//           email: "$user.email",
//           phone: "$user.phone",
//           lastMessage: {
//             $cond: [
//               { $eq: ["$lastMessage", null] },
//               "",
//               "$lastMessage",
//             ],
//           },
//           time: {
//             $cond: [
//               { $eq: ["$time", null] },
//               new Date().toISOString(),
//               "$time",
//             ],
//           },
//           unreadCount: 1,
//         },
//       },
//       {
//         $sort: { time: -1 },
//       },
//     ]);

//     res.status(200).json({
//       success: true,
//       data: chats,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });

// export const getChatList = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;

//     const mode = req.user.mode
    
//     console.log(mode, "mode")

//     const connections = await BuyerSellerConnection.find({
//       buyer: buyer,
//     })

//     const chats = await ChatMessage.aggregate([
//       {
//         $match: {
//           $or: [
//             { sender: new mongoose.Types.ObjectId(userId) },
//             { receiver: new mongoose.Types.ObjectId(userId) },
//           ],
//         },
//       },
//       { $sort: { createdAt: -1 } },
//       {
//         $group: {
//           _id: {
//             $cond: [
//               { $eq: ["$sender", new mongoose.Types.ObjectId(userId)] },
//               "$receiver",
//               "$sender",
//             ],
//           },
//           lastMessage: { $first: "$message" },
//           time: { $first: "$createdAt" },
//           unreadCount: {
//             $sum: {
//               $cond: [
//                 {
//                   $and: [
//                     { $eq: ["$receiver", new mongoose.Types.ObjectId(userId)] },
//                     { $eq: ["$isRead", false] },
//                   ],
//                 },
//                 1,
//                 0,
//               ],
//             },
//           },
//         },
//       },
//       {
//         $lookup: {
//           from: "users",
//           localField: "_id",
//           foreignField: "_id",
//           as: "user",
//         },
//       },
//       { $unwind: "$user" },
//       // 🔹 Exclude logged-in user from the result
//       {
//         $match: {
//           "user._id": { $ne: new mongoose.Types.ObjectId(userId) },
//         },
//       },
//       {
//         $project: {
//           _id: 1, // ID of the other user
//           name: "$user.name",
//           email: "$user.email",
//           phone: "$user.phone",
//           lastMessage: { $ifNull: ["$lastMessage", ""] },
//           time: { $ifNull: ["$time", new Date()] },
//           unreadCount: 1,
//         },
//       },
//       { $sort: { time: -1 } },
//     ]);

//     res.status(200).json({
//       success: true,
//       data: chats,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });


// export const getChatList = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode;
    
//     console.log(mode, "mode");

//     // Get all accepted connections based on user mode
//     let connectionFilter = { status: "Accepted" };

//     if (mode === "buyer") {
//       connectionFilter.buyer = userId;
//     } else if (mode === "seller") {
//       connectionFilter.seller = userId;
//     }

//     const connections = await BuyerSellerConnection.find(connectionFilter);

//     // Extract all connected user IDs
//     const connectedUserIds = connections.map(connection => {
//       if (mode === "buyer") {
//         return connection.seller; // For buyer, get all seller IDs
//       } else if (mode === "seller") {
//         return connection.buyer; // For seller, get all buyer IDs
//       }
//     });

//     console.log("Connected User IDs:", connectedUserIds);

//     // If no connections found, return empty array
//     if (connectedUserIds.length === 0) {
//       return res.status(200).json({
//         success: true,
//         data: [],
//       });
//     }

//     const chats = await ChatMessage.aggregate([
//       {
//         $match: {
//           $or: [
//             { 
//               sender: new mongoose.Types.ObjectId(userId),
//               receiver: { $in: connectedUserIds }
//             },
//             { 
//               receiver: new mongoose.Types.ObjectId(userId),
//               sender: { $in: connectedUserIds }
//             },
//           ],
//         },
//       },
//       { $sort: { createdAt: -1 } },
//       {
//         $group: {
//           _id: {
//             $cond: [
//               { $eq: ["$sender", new mongoose.Types.ObjectId(userId)] },
//               "$receiver",
//               "$sender",
//             ],
//           },
//           lastMessage: { $first: "$message" },
//           time: { $first: "$createdAt" },
//           unreadCount: {
//             $sum: {
//               $cond: [
//                 {
//                   $and: [
//                     { $eq: ["$receiver", new mongoose.Types.ObjectId(userId)] },
//                     { $eq: ["$isRead", false] },
//                   ],
//                 },
//                 1,
//                 0,
//               ],
//             },
//           },
//         },
//       },
//       {
//         $lookup: {
//           from: "users",
//           localField: "_id",
//           foreignField: "_id",
//           as: "user",
//         },
//       },
//       { $unwind: "$user" },
//       // Only show connected users
//       {
//         $match: {
//           "_id": { $in: connectedUserIds }
//         }
//       },
//       {
//         $project: {
//           _id: 1, // ID of the other user
//           name: "$user.name",
//           email: "$user.email",
//           phone: "$user.phone",
//           lastMessage: { $ifNull: ["$lastMessage", ""] },
//           time: { $ifNull: ["$time", new Date()] },
//           unreadCount: 1,
//         },
//       },
//       { $sort: { time: -1 } },
//     ]);

//     res.status(200).json({
//       success: true,
//       data: chats,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });
// export const getChatList = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode;
    
//     console.log("User ID:", userId);
//     console.log("Mode:", mode);

//     // Get all accepted connections based on user mode
//     let connectionFilter = { status: "Accepted" };

//     if (mode === "buyer") {
//       // Use the correct field names from your database
//       connectionFilter.buyer = userId;
//     } else if (mode === "seller") {
//       // Use the correct field names from your database
//       connectionFilter.seller = userId;
//     }

//     console.log("Connection Filter:", JSON.stringify(connectionFilter, null, 2));

//     const connections = await BuyerSellerConnection.find(connectionFilter);
//     console.log("Found Connections:", connections.length);
//     console.log("Connections details:", JSON.stringify(connections, null, 2));

//     // Extract all connected user IDs
//     const connectedUserIds = connections.map(connection => {
//       if (mode === "buyer") {
//         return connection.seller; // For buyer, get seller IDs
//       } else if (mode === "seller") {
//         return connection.buyer; // For seller, get buyer IDs
//       }
//     }).filter(id => id); // Remove any null/undefined values

//     console.log("Connected User IDs:", connectedUserIds);

//     // If no connections found, return empty array
//     if (connectedUserIds.length === 0) {
//       // Let's check what's actually in the database
//       const allConnections = await BuyerSellerConnection.find({ status: "Accepted" });
//       console.log("All accepted connections in DB:", JSON.stringify(allConnections, null, 2));
      
//       return res.status(200).json({
//         success: true,
//         data: [],
//         message: "No connections found"
//       });
//     }

//     // Rest of your aggregation pipeline...
//     const chats = await ChatMessage.aggregate([
//       {
//         $match: {
//           $or: [
//             { sender: userId, receiver: { $in: connectedUserIds } },
//             { receiver: userId, sender: { $in: connectedUserIds } }
//           ]
//         }
//       },
//       { $sort: { createdAt: -1 } },
//       {
//         $group: {
//           _id: {
//             $cond: [
//               { $eq: ["$sender", userId] },
//               "$receiver",
//               "$sender",
//             ],
//           },
//           lastMessage: { $first: "$message" },
//           time: { $first: "$createdAt" },
//           unreadCount: {
//             $sum: {
//               $cond: [
//                 {
//                   $and: [
//                     { $eq: ["$receiver", userId] },
//                     { $eq: ["$isRead", false] },
//                   ],
//                 },
//                 1,
//                 0,
//               ],
//             },
//           },
//         },
//       },
//       {
//         $lookup: {
//           from: "users",
//           localField: "_id",
//           foreignField: "_id",
//           as: "user",
//         },
//       },
//       { $unwind: "$user" },
//       {
//         $project: {
//           _id: 1,
//           name: "$user.name",
//           email: "$user.email",
//           phone: "$user.phone",
//           lastMessage: { $ifNull: ["$lastMessage", ""] },
//           time: { $ifNull: ["$time", new Date()] },
//           unreadCount: 1,
//         },
//       },
//       { $sort: { time: -1 } },
//     ]);

//     console.log("Final chats:", chats);

//     res.status(200).json({
//       success: true,
//       data: chats,
//     });
//   } catch (error) {
//     console.error("Error in getChatList:", error);
//     // return next(new ErrorHandler(error.message, 500));
//   }
// });




// Get chat history between buyer & seller
export const getChatHistory = catchAsyncErrors(async (req, res, next) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user._id;
    console.log("getChatHistory: Fetching history for user:", userId, "by:", currentUserId);

    const messages = await ChatMessage.find({
      $or: [
        { sender: currentUserId, receiver: userId },
        { sender: userId, receiver: currentUserId },
      ],
    })
      .sort({ createdAt: 1 })
      .populate("sender", "name email phone")
      .populate("receiver", "name email phone");

    res.status(200).json({
      success: true,
      data: messages,
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// Mark all messages from userId as read
export const markAsRead = catchAsyncErrors(async (req, res, next) => {
  try {
    const { userId } = req.params;
    const me = req.user._id;

    await ChatMessage.updateMany(
      { sender: userId, receiver: me, isRead: false },
      { $set: { isRead: true } }
    );

    // Notify sender that messages were read
    req.io.to(userId.toString()).emit("messagesRead", {
      readerId: me.toString(),
    });

    res.status(200).json({
      success: true,
      message: "Messages marked as read",
    });
  } catch (err) {
    return next(new Errorhandler(err.message, 500));
  }
});


// export const getChatList = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode;
    
//     console.log("User ID:", userId);
//     console.log("Mode:", mode);

//     // Get all accepted connections based on user mode
//     let connectionFilter = { status: "Accepted" };
//     let connectedUserField = "";

//     // if (mode === "buyer") {
//     //   connectionFilter.buyer = userId;
//     //   connectedUserField = "seller";
//     // } else if (mode === "seller") {
//     //   connectionFilter.seller = userId;
//     //   connectedUserField = "buyer";
//     // }

//     if (mode === "buyer") {
//   connectionFilter = {
//     status: "Accepted",
//     $or: [{ buyer: userId }, { seller: userId }],
//   };
// } else if (mode === "seller") {
//   connectionFilter = {
//     status: "Accepted",
//     $or: [{ seller: userId }, { buyer: userId }],
//   };
// }


//     console.log("Connection Filter:", JSON.stringify(connectionFilter, null, 2));

//     // const connections = await BuyerSellerConnection.find(connectionFilter).populate(connectedUserField, "name email phone");
//     // console.log("Found Connections:", connections.length);

//     // // If no connections found, return empty array
//     // if (connections.length === 0) {
//     //   return res.status(200).json({
//     //     success: true,
//     //     data: [],
//     //   });
//     // }

//     // // Extract all connected user IDs and user details
//     // const connectedUsers = connections.map(connection => ({
//     //   _id: connection[connectedUserField]._id,
//     //   name: connection[connectedUserField].name,
//     //   email: connection[connectedUserField].email,
//     //   phone: connection[connectedUserField].phone,
//     //   connection: connection
//     // }));

//     const connections = await BuyerSellerConnection.find(connectionFilter)
//   .populate("buyer", "name email phone")
//   .populate("seller", "name email phone");

// const connectedUsers = connections.map((conn) => {
//   const isBuyer = conn.buyer._id.toString() === userId.toString();
//   const otherUser = isBuyer ? conn.seller : conn.buyer;
//   return {
//     _id: otherUser._id,
//     name: otherUser.name,
//     email: otherUser.email,
//     phone: otherUser.phone,
//     connection: conn,
//   };
// });

//     console.log("Connected Users:", connectedUsers);

//     // Get connected user IDs for message lookup
//     const connectedUserIds = connectedUsers.map(user => user._id);

//     // Try to find messages with these users
//     const chats = await ChatMessage.aggregate([
//       {
//         $match: {
//           $or: [
//             { sender: userId, receiver: { $in: connectedUserIds } },
//             { receiver: userId, sender: { $in: connectedUserIds } }
//           ]
//         }
//       },
//       { $sort: { createdAt: -1 } },
//       {
//         $group: {
//           _id: {
//             $cond: [
//               { $eq: ["$sender", userId] },
//               "$receiver",
//               "$sender",
//             ],
//           },
//           lastMessage: { $first: "$message" },
//           time: { $first: "$createdAt" },
//           unreadCount: {
//             $sum: {
//               $cond: [
//                 {
//                   $and: [
//                     { $eq: ["$receiver", userId] },
//                     { $eq: ["$isRead", false] },
//                   ],
//                 },
//                 1,
//                 0,
//               ],
//             },
//           },
//         },
//       },
//       {
//         $lookup: {
//           from: "users",
//           localField: "_id",
//           foreignField: "_id",
//           as: "user",
//         },
//       },
//       { $unwind: "$user" },
//       {
//         $project: {
//           _id: 1,
//           name: "$user.name",
//           email: "$user.email",
//           phone: "$user.phone",
//           lastMessage: { $ifNull: ["$lastMessage", ""] },
//           time: { $ifNull: ["$time", new Date()] },
//           unreadCount: 1,
//         },
//       },
//       { $sort: { time: -1 } },
//     ]);

//     console.log("Chats from messages:", chats);

//     // If no messages found, return connected users with empty chat data
//     if (chats.length === 0) {
//       const chatList = connectedUsers.map(user => ({
//         _id: user._id,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         lastMessage: "",
//         time: user.connection.updatedAt, // Use connection update time
//         unreadCount: 0,
//       }));

//       console.log("Returning connected users as chat list:", chatList);

//       return res.status(200).json({
//         success: true,
//         data: chatList,
//       });
//     }

//     console.log("Final chats:", chats);

//     res.status(200).json({
//       success: true,
//       data: chats,
//     });
//   } catch (error) {
//     console.error("Error in getChatList:", error);
//     return next(new Errorhandler(error.message, 500));
//   }
// });



export const getChatList = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode;

    console.log("User ID:", userId);
    console.log("Mode:", mode);

    // Get all accepted connections based on user mode
    let connectionFilter = { status: "Accepted" };

    if (mode === "buyer") {
      connectionFilter = {
        status: "Accepted",
        $or: [{ buyer: userId }, { seller: userId }],
      };
    } else if (mode === "seller") {
      connectionFilter = {
        status: "Accepted",
        $or: [{ seller: userId }, { buyer: userId }],
      };
    }

    console.log("Connection Filter:", JSON.stringify(connectionFilter, null, 2));

    // Fetch all connections with populated user info
    const connections = await BuyerSellerConnection.find(connectionFilter)
      .populate("buyer", "name email phone")
      .populate("seller", "name email phone");

    // Extract connected users
    const connectedUsers = connections.map((conn) => {
      const isBuyer = conn.buyer._id.toString() === userId.toString();
      const otherUser = isBuyer ? conn.seller : conn.buyer;
      return {
        _id: otherUser._id,
        name: otherUser.name,
        email: otherUser.email,
        phone: otherUser.phone,
        connection: conn,
      };
    });

    console.log("Connected Users:", connectedUsers);

    const connectedUserIds = connectedUsers.map((user) => user._id);

    // Fetch messages with these connected users
    const chats = await ChatMessage.aggregate([
      {
        $match: {
          $or: [
            { sender: userId, receiver: { $in: connectedUserIds } },
            { receiver: userId, sender: { $in: connectedUserIds } },
          ],
        },
      },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: {
            $cond: [{ $eq: ["$sender", userId] }, "$receiver", "$sender"],
          },
          lastMessage: { $first: "$message" },
          time: { $first: "$createdAt" },
          unreadCount: {
            $sum: {
              $cond: [
                { $and: [{ $eq: ["$receiver", userId] }, { $eq: ["$isRead", false] }] },
                1,
                0,
              ],
            },
          },
        },
      },
    ]);

    console.log("Chats from messages:", chats);

    // Map messages by userId for easy lookup
    const chatMap = {};
    chats.forEach((chat) => {
      chatMap[chat._id.toString()] = chat;
    });

    // Merge connected users with messages
    const finalChatList = connectedUsers.map((user) => {
      const chatData = chatMap[user._id.toString()] || {};
      return {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        lastMessage: chatData.lastMessage || "",
        time: chatData.time || user.connection.updatedAt,
        unreadCount: chatData.unreadCount || 0,
      };
    });

    // Sort by time (latest first)
    finalChatList.sort((a, b) => new Date(b.time) - new Date(a.time));

    console.log("Final Chat List:", finalChatList);

    return res.status(200).json({
      success: true,
      data: finalChatList,
    });
  } catch (error) {
    console.error("Error in getChatList:", error);
    return next(new Errorhandler(error.message, 500));
  }
});
