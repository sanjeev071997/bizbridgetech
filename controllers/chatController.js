// import mongoose from "mongoose";
// import ChatMessage from "../models/Chat.js";
// import User from "../models/userModel.js"
// import Errorhandler from "../utils/Errorhandler.js";
// import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
// import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";

// // Send message (store in DB + emit via Socket.IO)
// export const sendMessage = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const { receiverId, message } = req.body;
//     const senderId = req.user._id;

//     if (!receiverId || !message) {
//       return res.status(400).json({ 
//         success: false, 
//         message: "Receiver and message are required" 
//       });
//     }

//     const receiver = await User.findById(receiverId);

//     if (!receiver) {
//       return res.status(404).json({ 
//         success: false, 
//         message: "Receiver not found" 
//       });
//     }

//     const chat = await ChatMessage.create({
//       sender: senderId,
//       receiver: receiverId,
//       message,
//       createdAt: new Date().toISOString(),
//       isRead: false,
//     });

//     const populatedChat = await ChatMessage.findById(chat._id)
//       .populate("sender", "name email phone")
//       .populate("receiver", "name email phone");
    
//     if (req.io) {
//       console.log("Emitting receiveMessage to:",
//         // {
//         // sender: senderId.toString(),
//         // receiver: receiverId.toString()
//         // }
//     );
      
//       req.io.to(senderId.toString()).emit("receiveMessage", populatedChat);
//       req.io.to(receiverId.toString()).emit("receiveMessage", populatedChat);
      
//     } else {
//       console.error("req.io is not available");
//     }

//     res.status(201).json({
//       success: true,
//       message: "Message sent successfully",
//       data: populatedChat,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });

// // Get chat history between buyer & seller
// export const getChatHistory = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const { userId } = req.params;
//     const currentUserId = req.user._id;
//     const messages = await ChatMessage.find({
//       $or: [
//         { sender: currentUserId, receiver: userId },
//         { sender: userId, receiver: currentUserId },
//       ],
//     })
//       .sort({ createdAt: 1 })
//       .populate("sender", "name email phone")
//       .populate("receiver", "name email phone");

//     res.status(200).json({
//       success: true,
//       data: messages,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });

// // Mark all messages from userId as read
// export const markAsRead = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const { userId } = req.params;
//     const me = req.user._id;

//     await ChatMessage.updateMany(
//       { sender: userId, receiver: me, isRead: false },
//       { $set: { isRead: true } }
//     );

//     // Notify sender that messages were read
//     req.io.to(userId.toString()).emit("messagesRead", {
//       readerId: me.toString(),
//     });

//     res.status(200).json({
//       success: true,
//       message: "Messages marked as read",
//     });
//   } catch (err) {
//     return next(new Errorhandler(err.message, 500));
//   }
// });

// // Get Chat List with last message and unread count
// export const getChatList = catchAsyncErrors(async (req, res, next) => {
//   try {
//     const userId = req.user._id;
//     const mode = req.user.mode;

//     // Get all accepted connections based on user mode
//     let connectionFilter = { status: "Accepted" };

//     if (mode === "buyer") {
//       connectionFilter = {
//         status: "Accepted",
//         $or: [{ buyer: userId }, { seller: userId }],
//       };
//     } else if (mode === "seller") {
//       connectionFilter = {
//         status: "Accepted",
//         $or: [{ seller: userId }, { buyer: userId }],
//       };
//     }

//     // Fetch all connections with populated user info
//     const connections = await BuyerSellerConnection.find(connectionFilter)
//       .populate("buyer", "name email phone")
//       .populate("seller", "name email phone");

//     // Extract connected users
//     const connectedUsers = connections.map((conn) => {
//       const isBuyer = conn.buyer._id.toString() === userId.toString();
//       const otherUser = isBuyer ? conn.seller : conn.buyer;
//       return {
//         _id: otherUser._id,
//         name: otherUser.name,
//         email: otherUser.email,
//         phone: otherUser.phone,
//         connection: conn,
//       };
//     });

//     const connectedUserIds = connectedUsers.map((user) => user._id);

//     // Fetch messages with these connected users
//     const chats = await ChatMessage.aggregate([
//       {
//         $match: {
//           $or: [
//             { sender: userId, receiver: { $in: connectedUserIds } },
//             { receiver: userId, sender: { $in: connectedUserIds } },
//           ],
//         },
//       },
//       { $sort: { createdAt: -1 } },
//       {
//         $group: {
//           _id: {
//             $cond: [{ $eq: ["$sender", userId] }, "$receiver", "$sender"],
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
//     ]);

//     // Map messages by userId for easy lookup
//     const chatMap = {};
//     chats.forEach((chat) => {
//       chatMap[chat._id.toString()] = chat;
//     });

//     // Merge connected users with messages
//     const finalChatList = connectedUsers.map((user) => {
//       const chatData = chatMap[user._id.toString()] || {};
//       return {
//         _id: user._id,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         lastMessage: chatData.lastMessage || "",
//         time: chatData.time || user.connection.updatedAt,
//         unreadCount: chatData.unreadCount || 0,
//       };
//     });

//     // Sort by time (latest first)
//     finalChatList.sort((a, b) => new Date(b.time) - new Date(a.time));
//     return res.status(200).json({
//       success: true,
//       data: finalChatList,
//     });
//   } catch (error) {
//     return next(new Errorhandler(error.message, 500));
//   }
// });


// // One - to - One Chat System 

// import Conversation from "../models/Conversation.js";
// import Message from "../models/message.js";

// /**
//  * Create or Get Conversation (Buyer ↔ Seller)
//  */
// export const getOrCreateConversation = async (req, res) => {
//   const userId = req.user._id;
//   const { receiverId } = req.body;

//   if (!receiverId) {
//     return res.status(400).json({
//       success: false,
//       message: "Receiver ID is required",
//     });
//   }

//   let conversation = await Conversation.findOne({
//     members: { $all: [userId, receiverId] },
//   });

//   if (!conversation) {
//     conversation = await Conversation.create({
//       members: [userId, receiverId],
//     });
//   }

//   return res.status(200).json({
//     success: true,
//     data: conversation,
//   });
// };

// /**
//  * Get messages of a conversation
//  */
// export const getMessages = async (req, res) => {
//   const { conversationId } = req.params;

//   const messages = await Message.find({ conversationId })
//     .sort({ createdAt: 1 })
//     .populate("sender", "name email");

//   return res.status(200).json({
//     success: true,
//     data: messages,
//   });
// };

// /**
//  * Send message (DB save + socket emit)
//  */
// export const sendMessage = async (req, res) => {
//   const senderId = req.user._id;
//   const { conversationId, receiverId, text } = req.body;

//   if (!text) {
//     return res.status(400).json({
//       success: false,
//       message: "Message text is required",
//     });
//   }

//   const message = await Message.create({
//     conversationId,
//     sender: senderId,
//     receiver: receiverId,
//     text,
//   });

//   // Update conversation last message
//   await Conversation.findByIdAndUpdate(conversationId, {
//     lastMessage: text,
//     lastMessageAt: new Date(),
//   });

//   // Emit real-time message
//   if (req.io) {
//     req.io.to(receiverId.toString()).emit("receiveMessage", message);
//   }

//   return res.status(201).json({
//     success: true,
//     data: message,
//   });
// };




// import Conversation from "../models/Conversation.js";
// import Message from "../models/message.js";
// import User from "../models/userModel.js";

// /**
//  * Create or Get Conversation (Buyer ↔ Seller)
//  */
// export const getOrCreateConversation = async (req, res) => {
//   const userId = req.user._id;
//   const { receiverId } = req.body;

//   if (!receiverId) {
//     return res.status(400).json({ success: false, message: "Receiver ID is required" });
//   }

//   let conversation = await Conversation.findOne({
//     members: { $all: [userId, receiverId] },
//   });

//   if (!conversation) {
//     conversation = await Conversation.create({
//       members: [userId, receiverId],
//     });
//   }

//   return res.status(200).json({ success: true, data: conversation });
// };

// /**
//  * Get messages of a conversation (mode filtered)
//  */
// export const getMessages = async (req, res) => {
//   const { conversationId } = req.params;
//   const user = await User.findById(req.user._id);

//   if (!user) return res.status(404).json({ success: false, message: "User not found" });

//   const messages = await Message.find({ conversationId, mode: user.mode })
//     .sort({ createdAt: 1 })
//     .populate("sender", "name email");

//   return res.status(200).json({ success: true, data: messages });
// };

// /**
//  * Send message (DB save + socket emit)
//  */
// export const sendMessage = async (req, res) => {
//   const senderId = req.user._id;
//   const { conversationId, receiverId, text } = req.body;
//   const sender = await User.findById(senderId);

//   if (!text) {
//     return res.status(400).json({ success: false, message: "Message text is required" });
//   }

//   const message = await Message.create({
//     conversationId,
//     sender: senderId,
//     receiver: receiverId,
//     text,
//     mode: sender.mode, // save current mode
//   });

//   // Update conversation last message
//   await Conversation.findByIdAndUpdate(conversationId, {
//     lastMessage: text,
//     lastMessageAt: new Date(),
//   });

//   // Emit real-time message only if receiver is online
//   if (req.io) {
//     const receiverSocketId = req.io.onlineUsers?.get(receiverId.toString());
//     if (receiverSocketId) req.io.to(receiverSocketId).emit("receiveMessage", message);
//   }

//   return res.status(201).json({ success: true, data: message });
// };


// import Conversation from "../models/Conversation.js";
// import Message from "../models/message.js";
// import User from "../models/userModel.js";

// /**
//  * Create or Get Conversation (Buyer ↔ Seller)
//  */
// export const getOrCreateConversation = async (req, res) => {
//   try {
//     const userId = req.user._id;
//     const { receiverId } = req.body;

//     if (!receiverId) {
//       return res
//         .status(400)
//         .json({ success: false, message: "Receiver ID is required" });
//     }

//     let conversation = await Conversation.findOne({
//       members: { $all: [userId, receiverId] },
//     });

//     if (!conversation) {
//       conversation = await Conversation.create({
//         members: [userId, receiverId],
//       });
//     }

//     return res.status(200).json({ success: true, data: conversation });
//   } catch (error) {
//     console.error(error);
//     return res
//       .status(500)
//       .json({ success: false, message: "Server error" });
//   }
// };

// /**
//  * Get messages of a conversation (filtered by user mode)
//  */
// // export const getMessages = async (req, res) => {
// //   try {
// //     const { conversationId } = req.params;
// //     const user = await User.findById(req.user._id);

// //     if (!user)
// //       return res
// //         .status(404)
// //         .json({ success: false, message: "User not found" });

// //     // Filter messages by mode
// //     const messages = await Message.find({
// //       conversationId,
// //       mode: user.mode, // ✅ only get messages with user's current mode
// //     })
// //       .sort({ createdAt: 1 })
// //       .populate("sender", "name email");

// //     return res.status(200).json({ success: true, data: messages });
// //   } catch (error) {
// //     console.error(error);
// //     return res
// //       .status(500)
// //       .json({ success: false, message: "Server error" });
// //   }
// // };

// export const getMessages = async (req, res) => {
//   try {
//     const { conversationId } = req.params;
//     const user = await User.findById(req.user._id);

//     if (!user)
//       return res
//         .status(404)
//         .json({ success: false, message: "User not found" });

//     // 🔹 CRITICAL FIX: Get messages with OPPOSITE mode
//     const oppositeMode = user.mode === "seller" ? "buyer" : "seller";
    
//     const messages = await Message.find({
//       conversationId,
//       mode: oppositeMode, // ✅ Get messages with opposite mode
//     })
//       .sort({ createdAt: 1 })
//       .populate("sender", "name email");

//     return res.status(200).json({ success: true, data: messages });
//   } catch (error) {
//     console.error(error);
//     return res
//       .status(500)
//         .json({ success: false, message: "Server error" });
//   }
// };
// /**
//  * Send message (DB save + socket emit)
//  */
// // export const sendMessage = async (req, res) => {
// //   try {
// //     const senderId = req.user._id;
// //     const { conversationId, receiverId, text } = req.body;
// //     const sender = await User.findById(senderId);

// //     if (!text) {
// //       return res
// //         .status(400)
// //         .json({ success: false, message: "Message text is required" });
// //     }

// //     const message = await Message.create({
// //       conversationId,
// //       sender: senderId,
// //       receiver: receiverId,
// //       text,
// //       mode: sender.mode, // ✅ save current mode
// //     });

// //     // Update conversation last message
// //     await Conversation.findByIdAndUpdate(conversationId, {
// //       lastMessage: text,
// //       lastMessageAt: new Date(),
// //     });

// //     // Emit real-time message if receiver is online
// //     if (req.io) {
// //       const receiverSocketId = req.io.onlineUsers?.get(receiverId.toString());
// //       if (receiverSocketId)
// //         req.io.to(receiverSocketId).emit("receiveMessage", message);
// //     }

// //     return res.status(201).json({ success: true, data: message });
// //   } catch (error) {
// //     console.error(error);
// //     return res
// //       .status(500)
// //       .json({ success: false, message: "Server error" });
// //   }
// // };

// export const sendMessage = async (req, res) => {
//   try {
//     const senderId = req.user._id;
//     const { conversationId, receiverId, text } = req.body;
//     const sender = await User.findById(senderId);

//     if (!text) {
//       return res
//         .status(400)
//         .json({ success: false, message: "Message text is required" });
//     }

//     // 🔹 CRITICAL FIX: Store OPPOSITE mode
//     const oppositeMode = sender.mode === "seller" ? "buyer" : "seller";

//     const message = await Message.create({
//       conversationId,
//       sender: senderId,
//       receiver: receiverId,
//       text,
//       mode: oppositeMode, // ✅ Store opposite mode
//     });

//     // Update conversation last message
//     await Conversation.findByIdAndUpdate(conversationId, {
//       lastMessage: text,
//       lastMessageAt: new Date(),
//     });

//     // Emit real-time message if receiver is online
//     if (req.io) {
//       const receiverSocketId = req.io.onlineUsers?.get(receiverId.toString());
//       if (receiverSocketId) {
//         req.io.to(receiverSocketId).emit("receiveMessage", message);
//       }
//     }

//     return res.status(201).json({ success: true, data: message });
//   } catch (error) {
//     console.error(error);
//     return res
//       .status(500)
//       .json({ success: false, message: "Server error" });
//   }
// };

import Conversation from "../models/Conversation.js";
import Message from "../models/message.js";
import User from "../models/userModel.js";

/**
 * Create or Get Conversation (Buyer ↔ Seller)
 */
export const getOrCreateConversation = async (req, res) => {
  try {
    const userId = req.user._id;
    const { receiverId } = req.body;

    if (!receiverId) {
      return res
        .status(400)
        .json({ success: false, message: "Receiver ID is required" });
    }

    let conversation = await Conversation.findOne({
      members: { $all: [userId, receiverId] },
    });

    if (!conversation) {
      conversation = await Conversation.create({
        members: [userId, receiverId],
      });
    }

    return res.status(200).json({ success: true, data: conversation });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ success: false, message: "Server error" });
  }
};

/**
 * Get messages of a conversation
 * ⚠️ CHANGED: Don't filter by mode - show ALL messages for the conversation
 */
// export const getMessages = async (req, res) => {
//   try {
//     const { conversationId } = req.params;
//     const userId = req.user._id; // Current user ID

//     // Check if conversation exists and user is a member
//     const conversation = await Conversation.findById(conversationId);
    
//     if (!conversation) {
//       return res
//         .status(404)
//         .json({ success: false, message: "Conversation not found" });
//     }

//     // Check if user is part of this conversation
//     if (!conversation.members.includes(userId)) {
//       return res
//         .status(403)
//         .json({ success: false, message: "Access denied" });
//     }

//     // ⚠️ CHANGED: Get ALL messages for this conversation
//     const messages = await Message.find({
//       conversationId,
//     })
//       .sort({ createdAt: 1 })
//       .populate("sender", "name email");

//     console.log(`Found ${messages.length} messages for conversation ${conversationId}`);
    
//     return res.status(200).json({ 
//       success: true, 
//       data: messages,
//       count: messages.length 
//     });
//   } catch (error) {
//     console.error(error);
//     return res
//       .status(500)
//       .json({ success: false, message: "Server error" });
//   }
// };

export const getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const user = await User.findById(req.user._id);
     
    const mode = req.user.mode;
    console.log("mode", mode);

    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    // Get all messages
    const messages = await Message.find({
      conversationId,
    })
      .sort({ createdAt: 1 })
      .populate("sender", "name email");

    // Group messages by mode for frontend
    const groupedMessages = {
      sellerMessages: messages.filter(msg => msg.mode === "seller"),
      buyerMessages: messages.filter(msg => msg.mode === "buyer"),
      allMessages: messages
    };

    return res.status(200).json({ 
      success: true, 
      data: groupedMessages,
      currentUserMode: user.mode 
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ success: false, message: "Server error" });
  }
};

// export const getMessages = async (req, res) => {
//   try {
//     const { conversationId } = req.params;

//     const user = await User.findById(req.user._id);
//     if (!user) {
//       return res
//         .status(404)
//         .json({ success: false, message: "User not found" });
//     }

//     const currentUserMode = user.mode; // buyer | seller

//     console.log("currentUserMode", currentUserMode);

//     // opposite mode decide karo
//     const oppositeMode =
//       currentUserMode === "buyer" ? "seller" : "buyer";

//     // sirf opposite user ke messages lao
//     const messages = await Message.find({
//       conversationId,
//       mode: oppositeMode,
//     })
//       .sort({ createdAt: 1 })
//       .populate("sender", "name email");

//     return res.status(200).json({
//       success: true,
//       data: messages,
//       currentUserMode,
//       showingMessagesOf: oppositeMode,
//     });
//   } catch (error) {
//     console.error(error);
//     return res
//       .status(500)
//       .json({ success: false, message: "Server error" });
//   }
// };

/**
 * Send message
 * ⚠️ CHANGED: Save the ACTUAL mode, not opposite
 */
export const sendMessage = async (req, res) => {
  try {
    const senderId = req.user._id;
    const { conversationId, receiverId, text } = req.body;
    const sender = await User.findById(senderId);
    const mode = req.user.mode;

    if (!text) {
      return res
        .status(400)
        .json({ success: false, message: "Message text is required" });
    }

    // Check conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res
        .status(404)
        .json({ success: false, message: "Conversation not found" });
    }

    // Check if sender is member of conversation
    if (!conversation.members.includes(senderId)) {
      return res
        .status(403)
        .json({ success: false, message: "Not a member of this conversation" });
    }

    // ⚠️ CHANGED: Save ACTUAL sender mode, not opposite
    const message = await Message.create({
      conversationId,
      sender: senderId,
      receiver: receiverId,
      text,
      mode, // ✅ Save actual sender mode
    });

    // Update conversation last message
    await Conversation.findByIdAndUpdate(conversationId, {
      lastMessage: text,
      lastMessageAt: new Date(),
    });

    // Emit real-time message if receiver is online
    if (req.io) {
      const receiverSocketId = req.io.onlineUsers?.get(receiverId.toString());
      if (receiverSocketId) {
        req.io.to(receiverSocketId).emit("receiveMessage", message);
      }
    }

    return res.status(201).json({ 
      success: true, 
      data: message,
      message: "Message sent successfully" 
    });
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ success: false, message: "Server error" });
  }
};
