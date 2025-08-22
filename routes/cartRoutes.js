import express from "express";
import {
    addCart,
    getCart,
    removeCartItem,
    updateCartItem,
    clearCart,
} from "../controllers/cartController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

// Add item to cart 
router.post("/", isAuthenticatedUser, addCart);

// Get user cart
router.get("/", isAuthenticatedUser, getCart);

// Remove item from cart 
router.delete("/item/:itemId", isAuthenticatedUser, removeCartItem);

// Update item quantity 
router.put("/item/:itemId", isAuthenticatedUser, updateCartItem);

// Clear entire cart 
router.delete("/clear", isAuthenticatedUser, clearCart);

export default router;