// import User from "../models/userModel.js";
// import Message from "../models/message.js";

// const onlineUsers = new Map(); // userId -> socketId

// export const initSocket = (io) => {
//   io.on("connection", (socket) => {
//     console.log("User connected:", socket.id);

//     // =========================
//     // 🔹 USER ONLINE
//     // =========================
//     socket.on("userOnline", async (userId) => {
//       socket.userId = userId;
//       onlineUsers.set(userId, socket.id);

//       io.emit("onlineUsers", Array.from(onlineUsers.keys()));
//       console.log("User online:", userId);
//     });

//     // =========================
//     // 🔹 JOIN CHAT ROOM
//     // =========================
//     socket.on("joinChat", (userId) => {
//       socket.join(userId);
//       console.log(`User ${userId} joined room`);
//     });

//     // =========================
//     // 🔹 TYPING EVENTS
//     // =========================
//     socket.on("typing", ({ conversationId, senderId, receiverId }) => {
//       io.to(receiverId).emit("typing", { conversationId, senderId });
//     });

//     socket.on("stopTyping", ({ conversationId, senderId, receiverId }) => {
//       io.to(receiverId).emit("stopTyping", { conversationId, senderId });
//     });

//     // =========================
//     // ✅ MESSAGE DELIVERED (✓✓ grey)
//     // =========================
//     socket.on("messageDelivered", async ({ messageId, receiverId }) => {
//       await Message.findByIdAndUpdate(messageId, {
//         deliveredAt: new Date(),
//       });

//       io.to(receiverId).emit("messageStatusUpdated", {
//         messageId,
//         status: "delivered",
//       });
//     });

//     // =========================
//     // ✅ MESSAGE SEEN (✓✓ blue)
//     // =========================
//     socket.on("messageSeen", async ({ conversationId, userId }) => {
//       await Message.updateMany(
//         {
//           conversationId,
//           receiver: userId,
//           isRead: false,
//         },
//         {
//           isRead: true,
//           readAt: new Date(),
//         }
//       );

//       io.emit("messagesSeen", {
//         conversationId,
//         userId,
//       });
//     });

//     // =========================
//     // 🔹 DISCONNECT
//     // =========================
//     socket.on("disconnect", async () => {
//       const userId = socket.userId;
//       console.log("User disconnected:", socket.id, userId);

//       if (!userId) return;

//       onlineUsers.delete(userId);

//       // ✅ lastSeen FIX
//       await User.findByIdAndUpdate(userId, {
//         lastSeen: new Date(),
//       });

//       io.emit("onlineUsers", Array.from(onlineUsers.keys()));
//     });
//   });
// };


// import User from "../models/userModel.js";
// import Message from "../models/message.js";

// const onlineUsers = new Map(); // userId -> socketId

// export const initSocket = (io) => {
//   io.onlineUsers = onlineUsers; // attach map for controller use

//   io.on("connection", (socket) => {
//     console.log("User connected:", socket.id);

//     // 🔹 USER ONLINE
//     socket.on("userOnline", async (userId) => {
//       socket.userId = userId;
//       onlineUsers.set(userId, socket.id);

//       io.emit("onlineUsers", Array.from(onlineUsers.keys()));
//     });

//     // 🔹 JOIN CHAT ROOM
//     socket.on("joinChat", (userId) => socket.join(userId));

//     // 🔹 TYPING
//     socket.on("typing", ({ conversationId, senderId, receiverId }) =>
//       io.to(receiverId).emit("typing", { conversationId, senderId })
//     );

//     socket.on("stopTyping", ({ conversationId, senderId, receiverId }) =>
//       io.to(receiverId).emit("stopTyping", { conversationId, senderId })
//     );

//     // ✅ MESSAGE DELIVERED
//     socket.on("messageDelivered", async ({ messageId, receiverId }) => {
//       await Message.findByIdAndUpdate(messageId, { deliveredAt: new Date() });
//       io.to(receiverId).emit("messageStatusUpdated", { messageId, status: "delivered" });
//     });

//     // ✅ MESSAGE SEEN
//     socket.on("messageSeen", async ({ conversationId, userId }) => {
//       const user = await User.findById(userId);
//       if (!user) return;

//       await Message.updateMany(
//         { conversationId, receiver: userId, mode: user.mode, isRead: false },
//         { isRead: true, readAt: new Date() }
//       );

//       io.emit("messagesSeen", { conversationId, userId });
//     });

//     // 🔹 DISCONNECT
//     socket.on("disconnect", async () => {
//       const userId = socket.userId;
//       if (!userId) return;

//       onlineUsers.delete(userId);
//       await User.findByIdAndUpdate(userId, { lastSeen: new Date() });

//       io.emit("onlineUsers", Array.from(onlineUsers.keys()));
//     });
//   });
// };


import User from "../models/userModel.js";
import Message from "../models/message.js";

const onlineUsers = new Map(); // userId -> socketId

export const initSocket = (io) => {
  io.onlineUsers = onlineUsers; // attach map for controller use

  io.on("connection", (socket) => {
    console.log("User connected:", socket.id);

    // 🔹 USER ONLINE
    socket.on("userOnline", async (userId) => {
      socket.userId = userId;
      onlineUsers.set(userId, socket.id);

      io.emit("onlineUsers", Array.from(onlineUsers.keys()));
    });

    // 🔹 JOIN CHAT ROOM
    socket.on("joinChat", (userId) => socket.join(userId));

    // 🔹 TYPING (mode unaware, just user-based)
    socket.on("typing", ({ conversationId, senderId, receiverId }) =>
      io.to(receiverId).emit("typing", { conversationId, senderId })
    );

    socket.on("stopTyping", ({ conversationId, senderId, receiverId }) =>
      io.to(receiverId).emit("stopTyping", { conversationId, senderId })
    );

    // ✅ MESSAGE DELIVERED
    socket.on("messageDelivered", async ({ messageId, receiverId }) => {
      await Message.findByIdAndUpdate(messageId, { deliveredAt: new Date() });
      io.to(receiverId).emit("messageDelivered", { messageId });
    });

    // ✅ MESSAGE SEEN (mode-aware)
    // socket.on("messageSeen", async ({ messageId, userId }) => {
    //   const user = await User.findById(userId);
    //   if (!user) return;

    //   const message = await Message.findById(messageId);
    //   if (!message) return;

    //   // Only mark as read if message mode matches user's current mode
    //   if (message.mode === user.mode && !message.isRead) {
    //     message.isRead = true;
    //     message.readAt = new Date();
    //     await message.save();

    //     io.to(message.sender.toString()).emit("messageSeen", { messageId });
    //   }
    // });

    // ✅ MESSAGE SEEN (opposite mode-aware)
socket.on("messageSeen", async ({ messageId, userId }) => {
  const user = await User.findById(userId);
  if (!user) return;

  const message = await Message.findById(messageId);
  if (!message) return;

  // Only mark as read if message mode is OPPOSITE of user's current mode
  const oppositeMode = user.mode === "seller" ? "buyer" : "seller";
  
  if (message.mode === oppositeMode && !message.isRead) {
    message.isRead = true;
    message.readAt = new Date();
    await message.save();

    io.to(message.sender.toString()).emit("messageSeen", { messageId });
  }
});

    // 🔹 DISCONNECT
    socket.on("disconnect", async () => {
      const userId = socket.userId;
      if (!userId) return;

      onlineUsers.delete(userId);
      await User.findByIdAndUpdate(userId, { lastSeen: new Date() });

      io.emit("onlineUsers", Array.from(onlineUsers.keys()));
    });
  });
};
