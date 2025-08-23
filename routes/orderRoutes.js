import express from "express";
import { createOrder, getMyOrders, getSellerOrders, updateOrderStatus, deleteOrder } from "../controllers/orderController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/", isAuthenticatedUser, createOrder);
router.get("/my-orders", isAuthenticatedUser, getMyOrders);
router.get("/seller-orders", isAuthenticatedUser, getSellerOrders);
router.put("/:id", isAuthenticatedUser, updateOrderStatus);
router.delete("/:id", isAuthenticatedUser, deleteOrder);

export default router;
