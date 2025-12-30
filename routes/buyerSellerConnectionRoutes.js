import express from "express";
import { createBuyerSellerConnection, getBuyerConnections, updateConnectionStatus, assignedCategoryBuyerSeller, viewMembers } from "../controllers/buyerSellerConnectionController.js";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";

const router = express.Router();

// Create connection (user must be authenticated)
router.post("/connection", isAuthenticatedUser, createBuyerSellerConnection);

// Get all connections
router.get("/connection", isAuthenticatedUser, getBuyerConnections);

// Update connection status (buyer only)
router.put("/connection/:id/status", isAuthenticatedUser, updateConnectionStatus);

// Assigned Category
router.post("/assign/category", isAuthenticatedUser, assignedCategoryBuyerSeller)

// Get Buyer Category All Users -> (Seller Only)
router.post('/view-members', isAuthenticatedUser, viewMembers);


export default router;
