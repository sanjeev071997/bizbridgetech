import express from 'express';
import multer from 'multer';
import {
  createSellerCategory,
  getAllSellerCategories,
  getSellerCategoryById,
  updateSellerCategory,
  deleteSellerCategory,
  adminGetAllSellerCategories
} from '../controllers/sellerCategoryController.js';
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

router.post('/', upload.single('image'), isAuthenticatedUser, createSellerCategory);
router.get('/', isAuthenticatedUser, getAllSellerCategories);
router.get('/:id', isAuthenticatedUser, getSellerCategoryById);
router.put('/:id', upload.single('image'), isAuthenticatedUser, updateSellerCategory);
router.delete('/:id', isAuthenticatedUser, deleteSellerCategory);
// Admin route to get all seller categories
router.get('/admin/get', isAuthenticatedUser, isAdmin, adminGetAllSellerCategories);

export default router;
