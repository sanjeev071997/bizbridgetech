import express from "express";
import multer from "multer";
import {
  createTestimonial,
  getAllTestimonials,
  getUserTestimonials,
  updateTestimonial,
  deleteTestimonial,
} from "../controllers/testimonialController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

//  Create testimonial (only for authenticated users)
router.post("/",upload.single("image"), isAuthenticatedUser, createTestimonial);

// Get all testimonials (public)
router.get("/all", getAllTestimonials);

// Get current user's testimonials
router.get("/my", isAuthenticatedUser, getUserTestimonials);

// Update testimonial
router.put("/update/:id", isAuthenticatedUser, updateTestimonial);

// Delete testimonial
router.delete("/delete/:id",isAuthenticatedUser, deleteTestimonial);

export default router;
