import express from 'express';
import {
  createSellerCategory,
  getAllSellerCategories,
  getSellerCategoryById,
  updateSellerCategory,
  deleteSellerCategory,
  adminGetAllSellerCategories
} from '../controllers/sellerCategoryController.js';
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";
const router = express.Router();

router.post('/', isAuthenticatedUser, createSellerCategory);
router.get('/', isAuthenticatedUser, getAllSellerCategories);
router.get('/:id', isAuthenticatedUser, getSellerCategoryById);
router.put('/:id', isAuthenticatedUser, updateSellerCategory);
router.delete('/:id', isAuthenticatedUser, deleteSellerCategory);
// Admin route to get all seller categories
router.get('/admin/get', isAuthenticatedUser, isAdmin, adminGetAllSellerCategories);

export default router;
