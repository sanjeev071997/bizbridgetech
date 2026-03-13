import express from "express";
import { createOrder, getBuyerOrders, getSellerOrders, updateOrderStatus, updateProcessStep, deleteOrder, updateOrderItem, updateOrderProcessStep, getSuperAdminOrders, buyerOrders } from "../controllers/orderController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/create", isAuthenticatedUser, createOrder);
router.get("/buyer-orders", isAuthenticatedUser, getBuyerOrders);
router.get("/seller-orders", isAuthenticatedUser, getSellerOrders);
router.put("/:id", isAuthenticatedUser, updateOrderStatus); // seller order status update
router.patch("/:orderId/process-step", isAuthenticatedUser, updateProcessStep)
router.post("/update-process-step",isAuthenticatedUser, updateOrderProcessStep);
router.post("/update-item-quantity", isAuthenticatedUser, updateOrderItem); // update order item quantity
// Admin 
router.get("/admin", isAuthenticatedUser, isAdmin, getSuperAdminOrders); // get all order for super admin
router.delete("/admin/:id", isAuthenticatedUser, isAdmin, deleteOrder); // delete order for super admin


router.post("/get-buyer-orders", isAuthenticatedUser, buyerOrders)

export default router;
