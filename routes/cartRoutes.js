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
router.post("/get", isAuthenticatedUser, getCart);
router.delete("/remove", isAuthenticatedUser, removeItemFromCart);
router.delete("/clear", isAuthenticatedUser, clearCart);

export default router;