import express from "express";
import { createOrder, getBuyerOrders, getSellerOrders, updateOrderStatus, updateProcessStep, deleteOrder, updateOrderItem, updateOrderProcessStep } from "../controllers/orderController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/create", isAuthenticatedUser, createOrder);
router.get("/buyer-orders", isAuthenticatedUser, getBuyerOrders);
router.get("/seller-orders", isAuthenticatedUser, getSellerOrders);
router.put("/:id", isAuthenticatedUser, updateOrderStatus); // seller order status update
router.patch("/:orderId/process-step", isAuthenticatedUser, updateProcessStep)

router.post("/update-process-step",isAuthenticatedUser, updateOrderProcessStep);

router.post("/update-item-quantity", isAuthenticatedUser, updateOrderItem); // update order item quantity

router.delete("/:id", isAuthenticatedUser, deleteOrder); // delete order

export default router;
