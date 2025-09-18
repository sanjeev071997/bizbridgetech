import express from "express";
import multer from 'multer';
import {
  createAdvertisement,
  getAllAdvertisements,
  getAdvertisementById,
  updateAdvertisement,
  deleteAdvertisement,
  getAdvertisementsByCategory,
  getAdvertisementsByUserId,
} from "../controllers/advertisementController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";
// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

router.post("/create", upload.single('image'), isAuthenticatedUser, createAdvertisement); // Create advertisement

router.get("/all",isAuthenticatedUser, getAllAdvertisements); // Get all advertisements

router.get("/:id", isAuthenticatedUser, getAdvertisementById); // Get advertisement by ID

router.put("/update/:id", upload.single('image'), isAuthenticatedUser, updateAdvertisement); // Update advertisement

router.delete("/delete/:id", isAuthenticatedUser, deleteAdvertisement); // Delete advertisement

router.get("/category/:categoryId",getAdvertisementsByCategory); // Get advertisements by category

router.get("/user/:userId",isAuthenticatedUser,getAdvertisementsByUserId); // Get advertisements by user ID

export default router;
