import express from "express";
import { createBuyerSellerConnection, getBuyerConnections, updateConnectionStatus } from "../controllers/buyerSellerConnectionController.js";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";


const router = express.Router();

// Create connection (user must be authenticated)
router.post("/connection", isAuthenticatedUser, createBuyerSellerConnection);

// Get all connections
router.get("/connection", isAuthenticatedUser, getBuyerConnections);

// Update connection status (buyer only)
router.put("/connection/:id/status", isAuthenticatedUser, updateConnectionStatus);

export default router;
