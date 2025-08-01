import express from "express";
import multer from 'multer';
import {
  addProduct,
  getProductsByCategoryId,
  getProductById,
  updateProduct,
  deleteProduct,
  getAllProducts,
} from "../controllers/sellerProductController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

router.post("/", upload.single('image'), isAuthenticatedUser, addProduct);

router.get("/:category", isAuthenticatedUser, getProductsByCategoryId);

router.get("/:id", isAuthenticatedUser, getProductById); // Single Product 

router.put("/:id", upload.single('image'), isAuthenticatedUser, updateProduct);

router.delete("/:id", isAuthenticatedUser, deleteProduct);

router.get("/", isAuthenticatedUser, getAllProducts);

export default router;
