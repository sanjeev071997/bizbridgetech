// import express from "express";
// import {
//     addCart,
//     getCart,
//     removeCartItem,
//     updateCartItem,
//     clearCart,
// } from "../controllers/cartController.js";
// import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

// const router = express.Router();

// // Add item to cart 
// router.post("/", isAuthenticatedUser, addCart);

// // Get user cart
// router.get("/", isAuthenticatedUser, getCart);

// // Remove item from cart 
// router.delete("/item/:itemId", isAuthenticatedUser, removeCartItem);

// // Update item quantity 
// router.put("/item/:itemId", isAuthenticatedUser, updateCartItem);

// // Clear entire cart 
// router.delete("/clear", isAuthenticatedUser, clearCart);

// export default router;

import express from "express";
import {
  addCart,
  updateCart,
  paymentOptionUpdate,
  getCart,
  removeItemFromCart,
  clearCart,
} from "../controllers/cartController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";


const router = express.Router();

router.post("/add", isAuthenticatedUser, addCart);
router.put("/update", isAuthenticatedUser, updateCart);
router.put("/payment", isAuthenticatedUser, paymentOptionUpdate);
router.get("/:userId", isAuthenticatedUser, getCart);
router.delete("/remove", isAuthenticatedUser, removeItemFromCart);
router.delete("/clear", isAuthenticatedUser, clearCart);

export default router;
