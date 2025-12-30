import express from "express";
import {
sellerDashboard,
buyerDashboard
} from "../controllers/dashboardController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.get("/seller", isAuthenticatedUser, sellerDashboard);

router.get("/buyer", isAuthenticatedUser, buyerDashboard);


export default router;