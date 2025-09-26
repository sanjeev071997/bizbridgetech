import express from "express";
import { createOrder, getBuyerOrders, getSellerOrders, updateOrderStatus, updateProcessStep, deleteOrder } from "../controllers/orderController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/create", isAuthenticatedUser, createOrder);
router.get("/buyer-orders", isAuthenticatedUser, getBuyerOrders);
router.get("/seller-orders", isAuthenticatedUser, getSellerOrders);
router.put("/:id", isAuthenticatedUser, updateOrderStatus); // seller order status update
router.patch("/:orderId/process-step", isAuthenticatedUser, updateProcessStep)

router.delete("/:id", isAuthenticatedUser, deleteOrder); // Todo api check in postman 

export default router;
