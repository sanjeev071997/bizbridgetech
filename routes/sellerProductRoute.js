import express from "express";
import multer from 'multer';
import {
  addProduct,
  getProductsByCategoryId,
  getProductById,
  updateProduct,
  deleteProduct,
  getAllProducts,
  getProductByUserId,
} from "../controllers/sellerProductController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

router.post("/", upload.single('image'), isAuthenticatedUser, addProduct);

router.get("/:category", isAuthenticatedUser, getProductsByCategoryId);

router.get("/get/product/:id", isAuthenticatedUser, getProductById);

router.put("/:id", upload.single('image'), isAuthenticatedUser, updateProduct);

router.delete("/:id", isAuthenticatedUser, deleteProduct);

router.get("/", isAuthenticatedUser, getAllProducts);

router.get("/get/user/product", isAuthenticatedUser, getProductByUserId)

export default router;
