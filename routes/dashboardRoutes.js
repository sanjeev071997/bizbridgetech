import express from "express";
import {
sellerDashboard
} from "../controllers/dashboardController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.get("/seller", isAuthenticatedUser, sellerDashboard);

export default router;