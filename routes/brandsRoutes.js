import express from "express";
import multer from "multer";
import {
  createBrand,
  getAllBrands,
  deleteBrand,
} from "../controllers/brandsController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

router.post("/create", upload.single("image"), isAuthenticatedUser, isAdmin, createBrand ); // Create advertisement

router.get("/all", getAllBrands); // Get all advertisements

router.delete("/delete/:id", isAuthenticatedUser, isAdmin, deleteBrand); // Delete advertisement

export default router;