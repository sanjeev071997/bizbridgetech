import mongoose from "mongoose";
import ChatMessage from "../models/Chat.js";
import User from "../models/userModel.js"
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
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
      console.log("Emitting receiveMessage to:",
        // {
        // sender: senderId.toString(),
        // receiver: receiverId.toString()
        // }
    );
      
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

// Get chat history between buyer & seller
export const getChatHistory = catchAsyncErrors(async (req, res, next) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user._id;
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

// Get Chat List with last message and unread count
export const getChatList = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode;

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
    return res.status(200).json({
      success: true,
      data: finalChatList,
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});
