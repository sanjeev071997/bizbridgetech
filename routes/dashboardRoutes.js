import express from "express";
import {
sellerDashboard,
buyerDashboard,
superAdminDashboard,
} from "../controllers/dashboardController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.get("/seller", isAuthenticatedUser, sellerDashboard);

router.get("/buyer", isAuthenticatedUser, buyerDashboard);

router.get("/super/admin", isAuthenticatedUser, isAdmin, superAdminDashboard);


export default router;