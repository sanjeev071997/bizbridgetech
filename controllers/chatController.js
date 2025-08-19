import ChatMessage from "../models/Chat.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Send message (store in DB + emit via Socket.IO)
export const sendMessage = catchAsyncErrors(async (req, res, next) => {
  try {
    const { receiverId, message, } = req.body;
    const senderId = req.user._id;
    if (!receiverId || !message) {
      return res
        .status(400)
        .json({ success: false, message: "Receiver & message required" });
    }

    const chat = await ChatMessage.create({
      sender: senderId,
      receiver: receiverId,
      message,
    });

    // Emit real-time message to receiver
    req.io.to(receiverId.toString()).emit("receiveMessage", chat);

    res.status(201).json({
      success: true,
      message: "Message sent successfully",
      data: chat,
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

// Get chat history between buyer & seller
export const getChatHistory = catchAsyncErrors(async (req, res, next) => {
  try {
    const { userId } = req.params; // opposite person id
    const myId = req.user._id;

    const messages = await ChatMessage.find({
      $or: [
        { sender: myId, receiver: userId },
        { sender: userId, receiver: myId },
      ],
    }).populate("sender", "name email phone")
    .populate("receiver", "name email phone")
    .sort({ createdAt: 1 });

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
