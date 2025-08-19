import express from "express";
import { sendMessage, getChatHistory, markAsRead } from "../controllers/chatController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Send a message
router.post("/", isAuthenticatedUser, sendMessage);

// Get chat history with a user
router.get("/history/:userId", isAuthenticatedUser, getChatHistory);


// Mark messages from a user as read
router.put("/read/:userId", isAuthenticatedUser, markAsRead);

export default router;
