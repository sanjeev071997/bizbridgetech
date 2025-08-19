import express from "express";
import {
  createScheme,
  getAllSchemes,
  getSchemeById,
  updateScheme,
  deleteScheme,
  toggleSchemeStatus
} from "../controllers/schemeController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/",isAuthenticatedUser, createScheme);

router.get("/", isAuthenticatedUser, getAllSchemes);

router.get("/:id", isAuthenticatedUser, getSchemeById);

router.put("/:id", isAuthenticatedUser, updateScheme);

router.delete("/:id",isAuthenticatedUser, deleteScheme);

router.patch("/:id/toggle", isAuthenticatedUser, toggleSchemeStatus);

export default router;
