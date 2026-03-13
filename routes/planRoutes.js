import express from "express";
import {
  createPlan,
  getAllPlans,
  getSinglePlan,
  updatePlan,
  deletePlan,
  calculatePlanPrice,
  getPlansWithExpiry,
  renewPlan,
  getAllPlansForSuperAdmin
} from "../controllers/planController.js";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";

const router = express.Router();

// Public/User routes
router.get("/:id", getSinglePlan);
router.get("/", getAllPlans);
router.get("/with-expiry", getPlansWithExpiry);

// Super admin routes
router.post("/", isAuthenticatedUser, isAdmin, createPlan);
router.put("/:id", isAuthenticatedUser, isAdmin, updatePlan);
router.delete("/:id", isAuthenticatedUser, isAdmin, deletePlan);
router.post("/:id/renew", isAuthenticatedUser, isAdmin, renewPlan);
router.post("/calculate", isAuthenticatedUser, isAdmin, calculatePlanPrice);
router.get("/admin/all", isAuthenticatedUser, isAdmin, getAllPlansForSuperAdmin);

export default router;
