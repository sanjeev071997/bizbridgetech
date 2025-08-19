import express from "express";
import { createSupport, getAllSupport, getSupportByUserId } from "../controllers/supportController.js";

import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";


const router = express.Router();

// Create support ticket
router.post("/", isAuthenticatedUser, createSupport);

// Get all support tickets
router.get("/", isAuthenticatedUser, getAllSupport);

// Get support tickets by user ID
router.get("/user", isAuthenticatedUser, getSupportByUserId);

export default router;
